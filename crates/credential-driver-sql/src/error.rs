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
//! # Credential Fernet key repository error.
use std::path::PathBuf;

use openstack_keystone_core::credential::CredentialProviderError;
use openstack_keystone_key_repository::KeyRepositoryError;
use thiserror::Error;

/// Errors from the Fernet key repository (ADR 0019 §4).
#[derive(Error, Debug)]
pub enum CredentialFernetError {
    /// I/O error reading/writing a key file.
    #[error("I/O error on key repository path {path:?}: {source}")]
    Io {
        #[source]
        source: std::io::Error,
        path: PathBuf,
    },

    /// A key file's contents could not be parsed as a Fernet key.
    #[error("key file `{0}` is not a valid Fernet key")]
    InvalidKey(i8),

    /// No usable key files were found in the repository.
    #[error("no Fernet keys found in the credential key repository")]
    KeysMissing,

    /// A key file decodes to the well-known Null Key and
    /// `insecure_allow_null_key` is not set (ADR 0019 §4, Security).
    #[error(
        "credential key repository contains the well-known Null Key; refusing to start (set \
         [credential] insecure_allow_null_key to override — production tolerance is zero)"
    )]
    NullKeyDetected,

    /// Fernet index arithmetic would overflow the `i8` file-naming scheme.
    #[error("key rotation index overflow")]
    IndexOverflow,

    /// Encryption/decryption failed (e.g. no active key could decrypt the
    /// blob).
    #[error("fernet decryption failed: all active keys were tried")]
    DecryptionFailed,

    /// Persisting a rotated/staged key file failed.
    #[error("failed to persist key file: {0}")]
    Persist(String),
}

impl From<KeyRepositoryError> for CredentialFernetError {
    fn from(err: KeyRepositoryError) -> Self {
        match err {
            KeyRepositoryError::Io { source, path } => Self::Io { source, path },
            KeyRepositoryError::KeysMissing => Self::KeysMissing,
            KeyRepositoryError::InvalidKey(idx) => Self::InvalidKey(idx),
            KeyRepositoryError::NullKeyDetected => Self::NullKeyDetected,
            KeyRepositoryError::IndexOverflow => Self::IndexOverflow,
            KeyRepositoryError::Persist(msg) => Self::Persist(msg),
            // Unreachable in practice: the credential repository never
            // configures a `run_as` uid/gid, the only path that produces
            // this variant. Mapped rather than left a `match` gap so this
            // conversion stays exhaustive if that ever changes.
            KeyRepositoryError::NixErrno { context, source } => {
                Self::Persist(format!("{context}: {source}"))
            }
            // Unreachable in practice: `RoleMissing`/`Crypto` are produced
            // only by the asymmetric (ES256/RS256) key repository (ADR
            // 0026), which the symmetric Fernet credential repository
            // never uses. Mapped rather than left a `match` gap so this
            // conversion stays exhaustive if that ever changes.
            KeyRepositoryError::RoleMissing(role) => {
                Self::Persist(format!("unexpected asymmetric key role missing: {role:?}"))
            }
            KeyRepositoryError::Crypto(msg) => Self::Persist(msg),
        }
    }
}

impl From<CredentialFernetError> for CredentialProviderError {
    fn from(source: CredentialFernetError) -> Self {
        match source {
            CredentialFernetError::NullKeyDetected => {
                CredentialProviderError::Encryption(source.to_string())
            }
            other => CredentialProviderError::Encryption(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_key_detected_converts_to_encryption_error_with_message() {
        let err: CredentialProviderError = CredentialFernetError::NullKeyDetected.into();
        match err {
            CredentialProviderError::Encryption(msg) => {
                assert!(msg.contains("Null Key"));
            }
            other => panic!("expected Encryption variant, got {other:?}"),
        }
    }

    #[test]
    fn test_other_variants_convert_to_encryption_error() {
        let err: CredentialProviderError = CredentialFernetError::KeysMissing.into();
        assert!(
            matches!(err, CredentialProviderError::Encryption(msg) if msg.contains("no Fernet keys"))
        );

        let err: CredentialProviderError = CredentialFernetError::DecryptionFailed.into();
        assert!(matches!(err, CredentialProviderError::Encryption(_)));
    }
}
