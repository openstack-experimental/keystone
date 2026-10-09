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
//! # Storage error type.
//!
//! [`StoreError`] is the heavy, implementation-specific error used inside
//! this crate. Across the [`StorageApi`](crate::StorageApi) boundary it is
//! converted into the lightweight
//! [`ApiStoreError`](crate::ApiStoreError) (see the `From` impl below) so consumers do not depend on Raft, Fjall or gRPC types.
//use std::io;

use openstack_keystone_storage_crypto::CryptoError;
use thiserror::Error;

use crate::types::*;

/// Keystone Store error.
///
/// Heavy error type containing all implementation-specific variants.
/// The `StorageApi` trait boundary uses `ApiStoreError` (lightweight).
#[derive(Error, Debug)]
pub enum StoreError {
    /// DistributedStorage configuration is unset.
    #[error("missing storage configuration")]
    ConfigMissing,

    /// Concurrent modification conflict (revision mismatch).
    #[error("concurrent modification conflict: {subject} — {description}")]
    Conflict {
        subject: String,
        description: String,
    },

    /// Cryptographic error (AES-GCM, nonce management, DEK).
    #[error(transparent)]
    Crypto {
        #[from]
        source: CryptoError,
    },

    /// Database error.
    #[error(transparent)]
    Fjall {
        #[from]
        source: fjall::Error,
    },

    #[error(transparent)]
    IO {
        #[from]
        source: std::io::Error,
    },

    /// Tasks join error.
    #[error(transparent)]
    Join {
        #[from]
        source: tokio::task::JoinError,
    },

    #[error(transparent)]
    Json {
        #[from]
        source: serde_json::Error,
    },

    /// Key is already present in the store while the call expects it to be
    /// unset.
    #[error("key is already set")]
    KeyPresent,

    #[error(transparent)]
    Other(#[from] eyre::Report),

    /// Parse int error.
    #[error(transparent)]
    ParseInt {
        #[from]
        source: std::num::ParseIntError,
    },

    /// A keyspace partition is quarantined due to repeated GCM tag failures.
    #[error("partition '{0}' is quarantined due to repeated GCM tag failures")]
    Quarantined(String),

    /// Raft config error.
    #[error(transparent)]
    RaftConfig {
        #[from]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Raft empty membership data error.
    #[error("raft membership information missing")]
    RaftEmptyMembership,

    /// Raft error.
    #[error(transparent)]
    RaftError {
        #[from]
        source: openraft::errors::RaftError<TypeConfig, ClientWriteError>,
    },

    /// Raft fatal error.
    #[error(transparent)]
    RaftFatal {
        #[from]
        source: openraft::errors::Fatal<TypeConfig>,
    },

    /// Raft initialization error.
    #[error(transparent)]
    RaftInitError {
        #[from]
        source:
            openraft::errors::RaftError<TypeConfig, openraft::errors::InitializeError<TypeConfig>>,
    },

    /// Raft leader is unknown.
    #[error("raft leader is not known")]
    RaftLeaderUnknown,

    /// Raft linear read error.
    #[error(transparent)]
    RaftLinearReadError {
        #[from]
        source: openraft::errors::RaftError<
            TypeConfig,
            openraft::errors::LinearizableReadError<TypeConfig>,
        >,
    },

    /// Raft membership error.
    #[error(transparent)]
    RaftMembership {
        #[from]
        source: openraft::errors::MembershipError<NodeId>,
    },

    /// Raft empty membership data error.
    #[error("raft required parameter {0} missing")]
    RaftMissingParameter(String),

    /// Raft RPC error.
    #[error(transparent)]
    RaftRPCError {
        #[from]
        source: openraft::errors::RPCError<TypeConfig>,
    },

    /// Rmp decode error.
    #[error(transparent)]
    RmpDecode {
        #[from]
        source: rmp_serde::decode::Error,
    },

    /// Rmp encode error.
    #[error(transparent)]
    RmpEncode {
        #[from]
        source: rmp_serde::encode::Error,
    },

    #[error(transparent)]
    Storage {
        #[from]
        source: openraft::StorageError<TypeConfig>,
    },

    /// Error from the storage-api layer.
    #[error(transparent)]
    StorageApi {
        #[from]
        source: openstack_keystone_storage_api::StoreError,
    },

    /// Tls configuration is unset.
    #[error("missing mTLS configuration")]
    TlsConfigMissing,

    /// Tonic status error.
    #[error(transparent)]
    TonicStatus {
        #[from]
        source: tonic::Status,
    },

    /// Tonic transport error.
    #[error(transparent)]
    TonicTransport {
        #[from]
        source: tonic::transport::Error,
    },

    /// The operation could not be completed with a linearizability guarantee
    /// (Raft `ReadIndex`/forwarding failed or was exhausted). Callers MUST
    /// NOT substitute a non-linearizable local read (security invariant 4).
    #[error("storage temporarily unavailable: {0}")]
    Unavailable(String),

    /// URI error.
    #[error(transparent)]
    Uri {
        #[from]
        source: http::uri::InvalidUri,
    },

    /// Non UTF8 data.
    #[error(transparent)]
    Utf8 {
        /// The source of the error.
        #[from]
        source: std::string::FromUtf8Error,
    },

    /// Per-record write version exceeded the rotation threshold.
    #[error("key '{0}' write rate exceeded (version {1} >= threshold)")]
    WriteRateExceeded(String, u32),
}

impl From<StoreError> for std::io::Error {
    fn from(value: StoreError) -> Self {
        std::io::Error::other(value.to_string())
    }
}

impl From<openraft::ConfigError> for StoreError {
    fn from(value: openraft::ConfigError) -> Self {
        Self::RaftConfig {
            source: Box::new(value),
        }
    }
}

/// Convert the heavy storage error type to the lightweight API error type.
impl From<StoreError> for crate::ApiStoreError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::ConfigMissing => Self::ConfigMissing,
            StoreError::Conflict {
                subject,
                description,
            } => Self::Conflict {
                subject,
                description,
            },
            StoreError::KeyPresent => Self::KeyPresent,
            StoreError::Quarantined(partition) => Self::Conflict {
                subject: partition,
                description: "partition quarantined due to repeated GCM tag failures".to_string(),
            },
            StoreError::WriteRateExceeded(key, version) => Self::Conflict {
                subject: key,
                description: format!(
                    "write rate exceeded at version {version}; DEK rotation required"
                ),
            },
            StoreError::Unavailable(msg) => Self::Unavailable(msg),
            _ => Self::Other(Box::new(e)),
        }
    }
}
