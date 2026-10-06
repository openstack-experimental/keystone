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
//! # JWS token provider configuration (ADR 0026 §10, Phase 0)
//!
//! Separate from `[fernet_tokens]`: this key repository holds an
//! asymmetric (ES256/RS256) keypair rather than a ring of symmetric Fernet
//! keys, in a Python-Keystone-compatible on-disk layout (`keystone-manage
//! create_jws_keypair`) so filesystem keys shared with Python Keystone
//! nodes work unchanged. Selected via `[token] provider = jws`.
use std::path::PathBuf;

use oslo_config::{ConfigSection, register_section};
use serde::Deserialize;

/// `[jws_tokens]` section of the JWS token driver.
#[derive(Debug, Deserialize, Clone)]
pub struct JwsTokensConfig {
    /// Path to the JWS signing keypair, in Python Keystone's
    /// `create_jws_keypair` on-disk layout.
    #[serde(default = "default_jws_key_repository")]
    pub key_repository: PathBuf,

    /// Allow starting (and signing/verifying with) the well-known Null Key.
    /// Exists solely as a transient migration aid; must be `false` in any
    /// real deployment. Mirrors `[fernet_tokens] insecure_allow_null_key`.
    #[serde(default)]
    pub insecure_allow_null_key: bool,
}

impl ConfigSection for JwsTokensConfig {
    const NAME: &'static str = "jws_tokens";
}

// Optional: a fernet-only deployment has no `[jws_tokens]` section and gets
// the defaults.
register_section!(JwsTokensConfig, default);

fn default_jws_key_repository() -> PathBuf {
    PathBuf::from("/etc/keystone/jws-keys/")
}

impl Default for JwsTokensConfig {
    fn default() -> Self {
        Self {
            key_repository: default_jws_key_repository(),
            insecure_allow_null_key: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let cfg = JwsTokensConfig::default();
        assert_eq!(cfg.key_repository, PathBuf::from("/etc/keystone/jws-keys/"));
        assert!(!cfg.insecure_allow_null_key);
    }

    #[test]
    fn test_deserialize_defaults_when_empty() {
        let cfg: JwsTokensConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.key_repository, PathBuf::from("/etc/keystone/jws-keys/"));
        assert!(!cfg.insecure_allow_null_key);
    }

    #[test]
    fn test_deserialize_overrides() {
        let cfg: JwsTokensConfig = serde_json::from_str(
            r#"{"key_repository": "/tmp/jws", "insecure_allow_null_key": true}"#,
        )
        .unwrap();
        assert_eq!(cfg.key_repository, PathBuf::from("/tmp/jws"));
        assert!(cfg.insecure_allow_null_key);
    }
}

#[cfg(test)]
mod registry_tests {
    use std::io::Write;

    use super::*;

    /// A deployment with no `[jws_tokens]` section still gets the defaults
    /// through the section registry.
    #[tokio::test]
    async fn absent_section_is_materialized_from_default() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"[auth]\nmethods = []\n[database]\nconnection = \"foo\"\n")
            .unwrap();
        let loaded = oslo_config::load_snapshot_from::<openstack_keystone_config::Config>(
            file.path().into(),
        )
        .await
        .unwrap();
        let section = loaded.view().require::<JwsTokensConfig>().unwrap().clone();
        assert_eq!(
            section.key_repository,
            PathBuf::from("/etc/keystone/jws-keys/")
        );
    }

    #[tokio::test]
    async fn section_is_read_from_the_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(
            b"[auth]\nmethods = []\n[database]\nconnection = \"foo\"\n[jws_tokens]\nkey_repository = /tmp/jws\n",
        )
        .unwrap();
        let loaded = oslo_config::load_snapshot_from::<openstack_keystone_config::Config>(
            file.path().into(),
        )
        .await
        .unwrap();
        assert_eq!(
            loaded
                .view()
                .require::<JwsTokensConfig>()
                .unwrap()
                .key_repository,
            PathBuf::from("/tmp/jws")
        );
    }
}
