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
//use std::io;

use thiserror::Error;

use crate::types::*;

/// Keystone Store error.
#[derive(Error, Debug)]
pub enum StoreError {
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

    #[error(transparent)]
    Json {
        #[from]
        source: serde_json::Error,
    },

    /// Key is already present in the store while the call expects it to be unset.
    #[error("key is already set")]
    KeyPresent,

    #[error("missing mTLS configuration")]
    TlsConfigMissing,

    /// Raft config error.
    #[error(transparent)]
    RaftConfig {
        #[from]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Raft empty membership data error.
    #[error("raft membership information missing")]
    RaftEmptyMembership,

    /// Raft initialization error.
    #[error(transparent)]
    RaftInitError {
        #[from]
        source:
            openraft::errors::RaftError<TypeConfig, openraft::errors::InitializeError<TypeConfig>>,
    },

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

    /// Raft leader is unknown.
    #[error("raft leader is not known")]
    RaftLeaderUnknown,

    /// Raft membership error.
    #[error(transparent)]
    RaftMembership {
        #[from]
        source: openraft::errors::MembershipError<NodeId>,
    },

    /// Raft empty membership data error.
    #[error("raft required parameter {0} missing")]
    RaftMissingParameter(String),

    /// Raft linear read error.
    #[error(transparent)]
    RaftLinearReadError {
        #[from]
        source: openraft::errors::RaftError<
            TypeConfig,
            openraft::errors::LinearizableReadError<TypeConfig>,
        >,
    },

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

    #[error(transparent)]
    Other(#[from] eyre::Report),
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
