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

//! Helpers for detecting and applying `[database]` TLS material rotation.
//!
//! Split out of `bin/keystone.rs` so the logic driving
//! `reconnect_db_on_config_change` is unit-testable outside a `bin` target.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

use sea_orm::ConnectOptions;
use secrecy::ExposeSecret;

use crate::config::{Config, TlsConfiguration};

/// Snapshot of `mtime()` for whichever of the three `[database]` TLS file
/// paths are currently configured, keyed by path. A path whose metadata
/// can't be read maps to `None`, which still participates in equality - so a
/// file that starts missing and later can be stat'd (or vice versa) is
/// treated as a change, erring toward reconnecting rather than missing a
/// rotation.
pub fn db_tls_mtimes(cfg: &Config) -> HashMap<PathBuf, Option<SystemTime>> {
    [
        &cfg.database.tls.tls_cert_file,
        &cfg.database.tls.tls_key_file,
        &cfg.database.tls.tls_client_ca_file,
    ]
    .into_iter()
    .flatten()
    .map(|p| {
        (
            p.clone(),
            std::fs::metadata(p).and_then(|m| m.modified()).ok(),
        )
    })
    .collect()
}

/// Layer `[database]` TLS material already loaded by `Config::finish_load`
/// (via `TlsConfiguration::read_certs`) onto `opt`, via sea-orm's
/// backend-specific connect-option hooks. Both hooks are registered
/// unconditionally; sea-orm only invokes the one matching the DSN's actual
/// scheme (`postgres://` vs `mysql://`), so no backend detection is needed
/// here. A no-op when no `[database]` TLS material is configured, so
/// deployments not using it see no behavior change.
pub fn apply_db_tls(opt: &mut ConnectOptions, tls: &TlsConfiguration) {
    if tls.tls_cert_content.is_none()
        && tls.tls_key_content.is_none()
        && tls.tls_client_ca_content.is_none()
    {
        return;
    }

    let ca = tls.tls_client_ca_content.clone();
    let cert = tls.tls_cert_content.clone();
    let key = tls.tls_key_content.clone();

    opt.map_sqlx_postgres_opts({
        let (ca, cert, key) = (ca.clone(), cert.clone(), key.clone());
        move |mut o| {
            if let Some(ca) = &ca {
                o = o.ssl_root_cert_from_pem(ca.expose_secret().to_vec());
            }
            if let Some(cert) = &cert {
                o = o.ssl_client_cert_from_pem(cert.expose_secret());
            }
            if let Some(key) = &key {
                o = o.ssl_client_key_from_pem(key.expose_secret());
            }
            o
        }
    });
    opt.map_sqlx_mysql_opts(move |mut o| {
        if let Some(ca) = &ca {
            o = o.ssl_ca_from_pem(ca.expose_secret().to_vec());
        }
        if let Some(cert) = &cert {
            o = o.ssl_client_cert_from_pem(cert.expose_secret());
        }
        if let Some(key) = &key {
            o = o.ssl_client_key_from_pem(key.expose_secret());
        }
        o
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn db_tls_mtimes_tracks_configured_paths_only() {
        let mut cfg = Config::default();
        assert!(db_tls_mtimes(&cfg).is_empty());

        let ca_file = NamedTempFile::new().unwrap();
        cfg.database.tls.tls_client_ca_file = Some(ca_file.path().to_path_buf());

        let mtimes = db_tls_mtimes(&cfg);
        assert_eq!(mtimes.len(), 1);
        assert!(mtimes.contains_key(&ca_file.path().to_path_buf()));
    }

    #[test]
    fn db_tls_mtimes_changes_when_file_is_rewritten() {
        let mut cert_file = NamedTempFile::new().unwrap();
        write!(cert_file, "cert").unwrap();

        let mut cfg = Config::default();
        cfg.database.tls.tls_cert_file = Some(cert_file.path().to_path_buf());

        let before = db_tls_mtimes(&cfg);

        // Ensure the filesystem's mtime resolution actually observes a
        // difference (some filesystems only have 1s granularity).
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(cert_file.path())
            .unwrap();
        f.write_all(b"rotated cert").unwrap();
        f.sync_all().unwrap();

        let after = db_tls_mtimes(&cfg);
        assert_ne!(before, after);
    }

    #[test]
    fn apply_db_tls_is_noop_without_any_material() {
        let tls = TlsConfiguration::default();
        let mut opt = ConnectOptions::new("postgres://u:p@h/db");
        // Must not panic; both hooks simply never fire since content is None.
        apply_db_tls(&mut opt, &tls);
    }

    #[test]
    fn apply_db_tls_registers_hooks_with_partial_material() {
        let tls = TlsConfiguration {
            tls_client_ca_content: Some(b"fake-ca-pem".to_vec().into()),
            ..Default::default()
        };

        let mut opt = ConnectOptions::new("postgres://u:p@h/db");
        apply_db_tls(&mut opt, &tls);
    }
}
