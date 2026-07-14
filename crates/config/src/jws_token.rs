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

use serde::Deserialize;

/// JWS token provider.
#[derive(Debug, Deserialize, Clone)]
pub struct JwsTokenProvider {
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

fn default_jws_key_repository() -> PathBuf {
    PathBuf::from("/etc/keystone/jws-keys/")
}

impl Default for JwsTokenProvider {
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
        let cfg = JwsTokenProvider::default();
        assert_eq!(cfg.key_repository, PathBuf::from("/etc/keystone/jws-keys/"));
        assert!(!cfg.insecure_allow_null_key);
    }

    #[test]
    fn test_deserialize_defaults_when_empty() {
        let cfg: JwsTokenProvider = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.key_repository, PathBuf::from("/etc/keystone/jws-keys/"));
        assert!(!cfg.insecure_allow_null_key);
    }

    #[test]
    fn test_deserialize_overrides() {
        let cfg: JwsTokenProvider = serde_json::from_str(
            r#"{"key_repository": "/tmp/jws", "insecure_allow_null_key": true}"#,
        )
        .unwrap();
        assert_eq!(cfg.key_repository, PathBuf::from("/tmp/jws"));
        assert!(cfg.insecure_allow_null_key);
    }
}
