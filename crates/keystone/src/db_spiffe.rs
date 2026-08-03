// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Keystone-managed SPIFFE writer for the `[database]` mTLS identity.
//!
//! sqlx 0.9 (pinned; sea-orm 2.0) has no API to inject a live
//! `rustls::ClientConfig` or per-handshake certificate resolver into
//! `PgConnectOptions`/`MySqlConnectOptions` - only a file path or one-time
//! inline PEM bytes set once per `Database::connect` call. True
//! per-handshake SPIFFE-native DB mTLS, as the Raft and HTTP listeners get
//! via `spiffe_rustls::mtls_client`/`mtls_server`, is therefore not
//! achievable without patching sqlx itself.
//!
//! This module instead bridges SPIRE material onto disk at the paths
//! configured via `[database] tls_cert_file`/`tls_key_file`/
//! `tls_client_ca_file`, reusing the same file-watch-and-reconnect consumer
//! (`Config::get_watch_files`, `reconnect_db_on_config_change` in
//! `bin/keystone.rs`, backed by [`crate::db_reload`]) that also serves
//! externally-managed certs (SPIRE Helper sidecar, cert-manager, manual ops
//! rotation). Rotation latency here is bounded by SPIRE push -> atomic file
//! write -> config-reload debounce -> reconnect, not per-handshake.
//!
//! The DB server's own certificate is verified against the SPIRE trust
//! bundle (written to `tls_client_ca_file`) using sqlx's own standard X.509
//! chain+hostname verification - **not** SPIFFE-ID/trust-domain
//! allow-listing (that requires `spiffe_rustls::authorizer`, which is
//! unreachable through sqlx's connection options). Operators requiring
//! `verify-full`/`VERIFY_IDENTITY` sslmode must ensure their SPIRE
//! deployment issues the DB server's certificate with a DNS SAN matching
//! its connection hostname - a SPIRE registration-entry detail outside
//! Keystone's control; `verify-ca`/`VerifyCa` is the safe default otherwise.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use eyre::{Report, WrapErr};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// File paths the writer keeps populated with Keystone's current SPIFFE
/// X.509 SVID and trust bundle.
pub struct DbSpiffeWriterConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub ca_file: PathBuf,
}

/// Run the writer until cancelled or the SPIFFE source is closed.
///
/// Best-effort by design: a failure to build the initial `X509Source`
/// (e.g. `SPIFFE_ENDPOINT_SOCKET` unset or the Workload API unreachable) is
/// returned to the caller to log, matching the other SPIFFE initialization
/// paths in `main()` - it must not block the rest of startup.
pub async fn run(cancel: CancellationToken, config: DbSpiffeWriterConfig) -> Result<(), Report> {
    let source = tokio::select! {
        res = spiffe::X509Source::new() => res.wrap_err("SPIFFE X509Source init for DB mTLS failed")?,
        () = cancel.cancelled() => return Ok(()),
    };

    write_current(&source, &config)?;
    info!("Wrote initial SPIFFE-sourced DB mTLS material");

    let mut updates = source.updated();
    loop {
        tokio::select! {
            result = updates.changed() => {
                match result {
                    Ok(_seq) => {
                        if let Err(error) = write_current(&source, &config) {
                            warn!(%error, "Failed to write rotated DB mTLS material from SPIFFE");
                        } else {
                            info!("Rewrote DB mTLS material after SPIFFE SVID rotation");
                        }
                    }
                    Err(_closed) => break,
                }
            }
            () = cancel.cancelled() => break,
        }
    }
    Ok(())
}

fn write_current(source: &spiffe::X509Source, config: &DbSpiffeWriterConfig) -> Result<(), Report> {
    let svid = source.svid().wrap_err("reading current SPIFFE SVID")?;
    let bundle_set = source
        .bundle_set()
        .wrap_err("reading current SPIFFE trust bundle")?;

    let cert_pem = svid
        .cert_chain()
        .iter()
        .map(|c| pem::encode(&pem::Pem::new("CERTIFICATE", c.as_bytes().to_vec())))
        .collect::<String>();
    atomic_write(&config.cert_file, cert_pem.as_bytes())
        .wrap_err("writing SPIFFE-sourced DB client certificate")?;

    let key_pem = pem::encode(&pem::Pem::new(
        "PRIVATE KEY",
        svid.private_key().as_bytes().to_vec(),
    ));
    atomic_write(&config.key_file, key_pem.as_bytes())
        .wrap_err("writing SPIFFE-sourced DB client key")?;

    let ca_pem = bundle_set
        .iter()
        .flat_map(|(_, bundle)| bundle.authorities().iter())
        .map(|c| pem::encode(&pem::Pem::new("CERTIFICATE", c.as_bytes().to_vec())))
        .collect::<String>();
    atomic_write(&config.ca_file, ca_pem.as_bytes())
        .wrap_err("writing SPIFFE trust bundle for DB server verification")?;

    Ok(())
}

/// Write `contents` to `path` via a same-directory temp file + rename, so
/// concurrent readers (the config file watcher, a connecting DB client)
/// never observe a partially-written file. Restricted to owner-only
/// permissions since the key file contains private key material.
fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), Report> {
    let tmp_path = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)
        .wrap_err_with(|| format!("creating temporary file {:?}", tmp_path))?;
    file.write_all(contents)
        .wrap_err_with(|| format!("writing temporary file {:?}", tmp_path))?;
    file.sync_all()
        .wrap_err_with(|| format!("syncing temporary file {:?}", tmp_path))?;
    std::fs::rename(&tmp_path, path)
        .wrap_err_with(|| format!("renaming {:?} to {:?}", tmp_path, path))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn atomic_write_produces_valid_pem_with_restricted_permissions() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cert.pem");

        let pem_body = pem::encode(&pem::Pem::new("CERTIFICATE", b"fake-der-bytes".to_vec()));
        atomic_write(&path, pem_body.as_bytes()).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written, pem_body);
        assert!(pem::parse(&written).is_ok());

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        // Old temp file must not linger after a successful rename.
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn atomic_write_overwrites_on_rotation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ca.pem");

        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"second");
    }
}
