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

//! Audit dispatcher bootstrap (ADR 0023 / ADR 0016-v2 §3.1): KEK
//! load-or-generate, per-node key derivation, spool replay, spool writers.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use color_eyre::eyre::{Report, Result, WrapErr};
use secrecy::{ExposeSecret, SecretBox};
use tokio::spawn;
use tracing::info;
use uuid::Uuid;

use crate::config::Config;
use openstack_keystone_audit::spool::{replay_spool, run_spool_writer, spool_path};
use openstack_keystone_audit::{AuditDispatcher, HmacKeyStore, derive_audit_hmac_key};

/// Version tag stamped on audit HMAC keys (ADR 0023 / ADR 0016-v2 §3.1).
const AUDIT_HMAC_KEY_VERSION: u64 = 1;

/// `MultiKeyStore` holds every key version seen during this process lifetime.
///
/// Currently only one version exists; the map is pre-populated with the
/// current key so `replay_spool` can verify events signed by it. When key
/// rotation is implemented, callers MUST insert the new version before
/// calling `refresh_hmac_key` on the dispatcher — spool events written
/// before the rotation still carry the old version number and must remain
/// verifiable during the drain window (ADR 0023 §"Key Rotation").
struct MultiKeyStore(HashMap<u64, Arc<[u8]>>);

impl HmacKeyStore for MultiKeyStore {
    fn get_key(&self, version: u64) -> Option<Arc<[u8]>> {
        self.0.get(&version).map(Arc::clone)
    }
}

/// Load the persisted 32-byte key-encryption-key (KEK) from `kek_file`, or
/// generate one from `/dev/urandom` and persist it atomically with `0600`
/// permissions if the file does not exist.
///
/// The KEK is not the HMAC signing key — a per-node key is derived from it
/// via HKDF-Expand (see [`derive_audit_hmac_key`]). Persisting the KEK lets a
/// restart re-derive the same per-node key and replay the spool.
///
/// The returned `SecretBox` zeroizes the bytes on drop.
fn load_or_generate_kek(kek_file: &Path) -> Result<SecretBox<Vec<u8>>, Report> {
    let bytes = match std::fs::read(kek_file) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                return Err(eyre::eyre!(
                    "audit KEK at {} is {} bytes — expected 32; \
                     delete the file to regenerate",
                    kek_file.display(),
                    bytes.len()
                ));
            }
            bytes
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use std::fs::OpenOptions;
            use std::io::{Read as _, Write as _};
            use std::os::unix::fs::OpenOptionsExt;
            let mut raw = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut raw))
                .wrap_err("failed to generate audit KEK from /dev/urandom")?;
            // Write to a temp file with restricted permissions, then
            // atomically rename. Avoids both a world-readable key file and a
            // TOCTOU window where two processes each generate independent keys.
            let tmp_path = kek_file.with_extension("tmp");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
                .wrap_err("failed to create temporary audit KEK file")?;
            file.write_all(&raw).wrap_err("failed to write audit KEK")?;
            std::fs::rename(&tmp_path, kek_file).wrap_err("failed to finalize audit KEK file")?;
            info!(path = %kek_file.display(), "generated new audit KEK");
            raw.to_vec()
        }
        Err(e) => {
            return Err(e).wrap_err("failed to read audit KEK; fix permissions or delete the file");
        }
    };
    Ok(SecretBox::new(Box::new(bytes)))
}

/// Load or generate the persisted audit HMAC key-encryption-key (KEK),
/// derive the per-node signing key, build the `AuditDispatcher`, replay any
/// events spooled by a previous run (at-least-once delivery), and spawn the
/// background spool writers for both QoS channels. See ADR 0023 / ADR
/// 0016-v2 §3.1.
pub async fn init(cfg: &Config) -> Result<Arc<AuditDispatcher>, Report> {
    let audit_cfg = cfg.audit.clone();
    let spool_dir = audit_cfg.spool_dir.clone();
    std::fs::create_dir_all(&spool_dir).wrap_err("failed to create audit spool directory")?;

    let audit_kek = load_or_generate_kek(&spool_dir.join("hmac-key.bin"))?;

    // Derive the per-node signing key:
    //   HKDF-Expand(KEK, info="keystone-audit-hmac-v1:{node_id}", L=32)
    // Per ADR 0023 / ADR 0016-v2 §3.1: per-node derivation ensures a
    // compromised node cannot forge records attributed to other nodes.
    let audit_hmac_key: Arc<[u8]> = Arc::from(
        derive_audit_hmac_key(audit_kek.expose_secret(), audit_cfg.node_id.as_str()).as_slice(),
    );

    let (audit_dispatcher, audit_receivers) = AuditDispatcher::new(
        audit_cfg.node_id.as_str(),
        Uuid::new_v4().to_string(),
        Arc::clone(&audit_hmac_key),
        AUDIT_HMAC_KEY_VERSION,
    );

    // Start background spool writers for both QoS channels BEFORE replay so
    // the critical channel (capacity 256) is drained as events are
    // dispatched. Without this, replay blocks indefinitely when the spool
    // has >256 events because no consumer is running.
    spawn(run_spool_writer(
        audit_receivers.perimeter,
        spool_dir.clone(),
        audit_cfg.node_id.clone(),
    ));
    spawn(run_spool_writer(
        audit_receivers.critical,
        spool_dir.clone(),
        audit_cfg.node_id.clone(),
    ));

    // Replay the spool file left by the previous run (at-least-once delivery).
    let mut key_store = MultiKeyStore(HashMap::new());
    key_store
        .0
        .insert(AUDIT_HMAC_KEY_VERSION, Arc::clone(&audit_hmac_key));
    let spool_file = spool_path(&spool_dir, audit_cfg.node_id.as_str());
    replay_spool(
        &spool_file,
        audit_cfg.node_id.as_str(),
        &audit_dispatcher,
        &key_store,
    )
    .await
    .wrap_err("audit spool replay failed")?;

    Ok(audit_dispatcher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_config(spool_dir: PathBuf) -> Config {
        let mut cfg = Config::default();
        cfg.audit.spool_dir = spool_dir;
        cfg.audit.node_id = "test-node".into();
        cfg
    }

    #[tokio::test]
    async fn init_audit_generates_and_reuses_kek() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path().to_path_buf());

        init(&cfg).await.expect("first init generates a KEK");
        let kek_file = tmp.path().join("hmac-key.bin");
        let generated = std::fs::read(&kek_file).expect("KEK file was written");
        assert_eq!(generated.len(), 32);

        // A second init on the same spool_dir must reuse the persisted KEK
        // rather than silently regenerating it (which would invalidate any
        // spooled events signed with the old key).
        init(&cfg).await.expect("second init reuses the KEK");
        let reused = std::fs::read(&kek_file).unwrap();
        assert_eq!(generated, reused);
    }

    #[tokio::test]
    async fn init_audit_rejects_wrong_length_kek() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path().to_path_buf());
        std::fs::create_dir_all(&cfg.audit.spool_dir).unwrap();
        std::fs::write(cfg.audit.spool_dir.join("hmac-key.bin"), b"too-short").unwrap();

        match init(&cfg).await {
            Ok(_) => panic!("expected init_audit to reject a wrong-length KEK"),
            Err(e) => assert!(e.to_string().contains("expected 32")),
        }
    }
}
