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
//! # Keystone distributed storage API
//!
//! Lightweight, object-safe trait and types for interacting with the
//! distributed storage backend.
//!
//! This crate provides the [`StorageApi`] trait, which is the only dependency
//! `core` has on the storage layer. It avoids pulling heavy implementation
//! dependencies (`openraft`, `tonic`, `fjall`, `serde_bytes`) into `core`.
//!
//! ## Design
//!
//! The trait uses concrete `Vec<u8>` types instead of generics to remain
//! object- safe. Callers serialize/deserialize at the trait boundary using
//! [`StoreDataEnvelope::try_serialize`] and
//! [`StoreDataEnvelope::try_deserialize`].
//!
//! ## Key types
//!
//! - [`StorageApi`] — the trait itself
//! - [`StoreDataEnvelope`] — data envelope with metadata, bridges typed/untyped
//! - [`StoreError`] — lightweight error (impl-specific errors → `Other`)
//! - [`StoreResponse`] — write operation response
//! - [`Mutation`] — batch transaction operations
//! - [`Metadata`] — revision and timestamp tracking
//! - [`Node`] — Raft cluster node descriptor

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Data sensitivity tier for at-rest encryption AD binding.
///
/// The tier byte is the first byte of the AES-GCM Associated Data in
/// `state_encrypt`, binding the sensitivity classification cryptographically to
/// the ciphertext.  Altering the tier in a stored record will fail tag
/// verification.
///
/// Tier 0–1 (Public, Internal) may be served from local state machine
/// reads without linearizability.  Tier 2–3 (Sensitive, Secret) require
/// a Raft `ReadIndex` round-trip before reading (Phase 2).
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum DataTier {
    /// Publicly readable data (e.g. service catalog).
    Public = 0,
    /// Internal keystone data (default).
    #[default]
    Internal = 1,
    /// Sensitive data (e.g. hashed credentials).
    Sensitive = 2,
    /// Secret data (e.g. application credentials).
    Secret = 3,
}

impl From<u8> for DataTier {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Public,
            1 => Self::Internal,
            2 => Self::Sensitive,
            3 => Self::Secret,
            _ => Self::Internal,
        }
    }
}

/// Lightweight error type for storage operations.
///
/// Contains only consumer-visible variants. Implementation-specific errors
/// (Raft, tonic, Fjall) are wrapped into [`Self::Other`].
#[derive(Error, Debug)]
pub enum StoreError {
    /// DistributedStorage configuration is unset.
    #[error("missing storage configuration")]
    ConfigMissing,

    /// Concurrent modification conflict (revision mismatch).
    #[error("concurrent modification conflict: {subject} — {description}")]
    Conflict {
        /// The resource or key the conflict refers to.
        subject: String,
        /// Human-readable description of the conflict.
        description: String,
    },

    /// Key is already present in the store while the call expects it to be
    /// unset.
    #[error("key is already set")]
    KeyPresent,

    /// Serialization error.
    #[error("serialization error")]
    Serialization(#[from] rmp_serde::encode::Error),

    /// Deserialization error.
    #[error("deserialization error")]
    Deserialize(#[from] rmp_serde::decode::Error),

    /// Invalid UTF-8 string.
    #[error("invalid utf-8")]
    Utf8(#[from] std::string::FromUtf8Error),

    /// Generic error for implementation-specific failures.
    #[error("{0}")]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl StoreError {
    /// Wraps an implementation-specific error into [`Self::Other`].
    pub fn other<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self::Other(err.into())
    }
}

/// Raft cluster node descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// Node identifier.
    pub node_id: u64,
    /// Node RPC address (host:port).
    pub rpc_addr: String,
}

/// Response from a storage write operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreResponse {
    /// Value returned from the operation (usually `None` for writes).
    pub value: Option<Vec<u8>>,

    /// Violations detected during the operation.
    pub violations: Vec<Violation>,
}

/// A single violation detected during a storage mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    /// Violation type, e.g. `"REVISION_MISMATCH"` or `"CONFLICT"`.
    pub r#type: String,

    /// The resource or key the violation refers to.
    pub subject: String,

    /// Human-readable description.
    pub description: String,
}

/// The metadata of stored data.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct Metadata {
    /// The resource revision.
    pub revision: u64,
    /// The timestamp when the resource was created.
    pub created_at: i64,
    /// Data sensitivity tier used for at-rest encryption AD and read-path
    /// enforcement.  Defaults to [`DataTier::Internal`].  Old records without
    /// this field (e.g. from a previous schema) deserialize to the default.
    #[serde(default)]
    pub tier: DataTier,
}

impl Metadata {
    /// Create new metadata with the current timestamp and `Internal` tier.
    pub fn new() -> Self {
        Self {
            revision: 0,
            created_at: Utc::now().timestamp(),
            tier: DataTier::Internal,
        }
    }

    /// Create new metadata with the given tier and the current timestamp.
    pub fn with_tier(tier: DataTier) -> Self {
        Self {
            revision: 0,
            created_at: Utc::now().timestamp(),
            tier,
        }
    }

    /// Create new metadata with an incremented revision, preserving timestamp
    /// and tier.
    pub fn new_revision(&self) -> Self {
        Self {
            revision: self.revision + 1,
            created_at: self.created_at,
            tier: self.tier,
        }
    }

    /// Serialize metadata into bytes using MessagePack format.
    /// Serialize metadata into MessagePack bytes.
    pub fn pack(&self) -> Result<Vec<u8>, StoreError> {
        Ok(rmp_serde::to_vec(self)?)
    }

    /// Deserialize metadata from MessagePack bytes.
    /// Deserialize metadata from MessagePack bytes.
    pub fn unpack(value: &[u8]) -> Result<Self, StoreError> {
        Ok(rmp_serde::from_slice(value)?)
    }
}

/// The envelope for transferring stored data with associated metadata.
#[derive(Debug, Deserialize, PartialEq)]
pub struct StoreDataEnvelope<T> {
    /// The resource metadata.
    pub metadata: Metadata,
    /// The resource data.
    pub data: T,
}

impl StoreDataEnvelope<Vec<u8>> {
    /// Deserialize the raw bytes into a typed value.
    ///
    /// # Returns
    /// A `Result` containing the deserialized `StoreDataEnvelope<T>`, or a
    /// `StoreError`.
    pub fn try_deserialize<T: DeserializeOwned>(&self) -> Result<StoreDataEnvelope<T>, StoreError> {
        Ok(StoreDataEnvelope {
            metadata: self.metadata.clone(),
            data: rmp_serde::from_slice(&self.data)?,
        })
    }
}

impl StoreDataEnvelope<String> {
    /// Serialize the string value into raw bytes.
    ///
    /// # Returns
    /// A `Result` containing the serialized `StoreDataEnvelope<Vec<u8>>`, or a
    /// `StoreError`.
    pub fn try_serialize(self) -> Result<StoreDataEnvelope<Vec<u8>>, StoreError> {
        Ok(StoreDataEnvelope {
            metadata: self.metadata,
            data: rmp_serde::to_vec(&self.data)?,
        })
    }
}

/// Store modification operation.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum Mutation {
    /// Delete the entry from the store.
    Remove {
        /// The key to remove.
        key: Vec<u8>,
        /// The keyspace the key belongs to.
        keyspace: String,
        /// Expected current revision (for optimistic concurrency).
        expected_revision: Option<u64>,
    },

    /// Delete the entry from the index store.
    RemoveIndex {
        /// The index key to remove.
        key: Vec<u8>,
    },

    /// Set the value for the key in the store.
    Set {
        /// Expected current revision (for optimistic concurrency).
        expected_revision: Option<u64>,
        /// The data key.
        key: Vec<u8>,
        /// The keyspace the key belongs to.
        keyspace: String,
        /// Resource metadata.
        metadata: Metadata,
        /// Serialized value bytes.
        value: Vec<u8>,
    },

    /// Set the value only if the key does not already exist.
    CreateIfAbsent {
        /// The data key.
        key: Vec<u8>,
        /// The keyspace the key belongs to.
        keyspace: String,
        /// Resource metadata.
        metadata: Metadata,
        /// Serialized value bytes.
        value: Vec<u8>,
    },

    /// Set the key in the index keyspace.
    SetIndex {
        /// The index key.
        key: Vec<u8>,
    },
}

impl Mutation {
    /// Create a remove mutation for the given key.
    pub fn remove<K, S>(key: K, keyspace: Option<S>, expected_revision: Option<u64>) -> Self
    where
        K: Into<Vec<u8>>,
        S: Into<String>,
    {
        Self::Remove {
            key: key.into(),
            keyspace: keyspace.map(Into::into).unwrap_or("data".into()),
            expected_revision,
        }
    }

    /// Create a remove_index mutation for the given key.
    pub fn remove_index<K>(key: K) -> Self
    where
        K: Into<Vec<u8>>,
    {
        Self::RemoveIndex { key: key.into() }
    }

    /// Create a set mutation.
    ///
    /// Returns `StoreError::Serialization` if `value` cannot be serialized.
    pub fn set<K, V, S>(
        key: K,
        value: V,
        metadata: Metadata,
        keyspace: Option<S>,
        expected_revision: Option<u64>,
    ) -> Result<Self, StoreError>
    where
        K: Into<Vec<u8>>,
        V: Serialize,
        S: Into<String>,
    {
        Ok(Self::Set {
            key: key.into(),
            value: rmp_serde::to_vec(&value)?,
            keyspace: keyspace.map(Into::into).unwrap_or("data".into()),
            metadata,
            expected_revision,
        })
    }

    /// Create a create-if-absent mutation.
    ///
    /// Returns `StoreError::Serialization` if `value` cannot be serialized.
    pub fn create_if_absent<K, V, S>(
        key: K,
        value: V,
        metadata: Metadata,
        keyspace: Option<S>,
    ) -> Result<Self, StoreError>
    where
        K: Into<Vec<u8>>,
        V: Serialize,
        S: Into<String>,
    {
        Ok(Self::CreateIfAbsent {
            key: key.into(),
            value: rmp_serde::to_vec(&value)?,
            keyspace: keyspace.map(Into::into).unwrap_or("data".into()),
            metadata,
        })
    }

    /// Create a set index mutation for the given key.
    /// Create a set_index mutation for the given key.
    pub fn set_index<K>(key: K) -> Self
    where
        K: Into<Vec<u8>>,
    {
        Self::SetIndex { key: key.into() }
    }
}

/// Distributed storage API.
///
/// Object-safe trait with concrete types instead of generics. Callers use
/// [`StoreDataEnvelope::try_serialize`] and
/// [`StoreDataEnvelope::try_deserialize`] for typed data at the boundary.
#[async_trait]
pub trait StorageApi: Send + Sync {
    /// Check whether a key exists in the given keyspace.
    async fn contains_key(&self, key: &[u8], keyspace: Option<&str>) -> Result<bool, StoreError>;

    /// Get a value by key.
    ///
    /// Returns `None` if the key does not exist. The result envelope contains
    /// raw bytes; use [`StoreDataEnvelope::try_deserialize`] to get typed data.
    async fn get_by_key(
        &self,
        key: &[u8],
        keyspace: Option<&str>,
    ) -> Result<Option<StoreDataEnvelope<Vec<u8>>>, StoreError>;

    /// List all entries with keys matching the given prefix.
    ///
    /// Returns raw bytes; use [`StoreDataEnvelope::try_deserialize`] on each
    /// envelope to get typed data.
    async fn prefix(
        &self,
        prefix: &[u8],
        keyspace: Option<&str>,
    ) -> Result<Vec<(String, StoreDataEnvelope<Vec<u8>>)>, StoreError>;

    /// List all index entries with keys matching the given prefix.
    async fn prefix_index(&self, prefix: &[u8]) -> Result<Vec<String>, StoreError>;

    /// Deletes a value for a given key.
    ///
    /// Returns `StoreResponse::KeyAbsent` if the key does not exist.
    async fn remove(
        &self,
        key: String,
        keyspace: Option<String>,
    ) -> Result<StoreResponse, StoreError>;

    /// Deletes index key.
    async fn remove_index(&self, key: String) -> Result<StoreResponse, StoreError>;

    /// Sets a value for a given key.
    ///
    /// The `value` envelope must contain pre-serialized bytes.
    /// Use [`StoreDataEnvelope::try_serialize`] to convert typed data.
    async fn set_value(
        &self,
        key: String,
        value: StoreDataEnvelope<Vec<u8>>,
        keyspace: Option<String>,
        expected_revision: Option<u64>,
    ) -> Result<StoreResponse, StoreError>;

    /// Sets an index key pointing to a data key.
    async fn set_index_key(&self, key: String) -> Result<StoreResponse, StoreError>;

    /// Mutation transaction.
    async fn transaction(&self, mutations: Vec<Mutation>) -> Result<StoreResponse, StoreError>;

    /// Checks if the Raft cluster is initialized.
    async fn is_initialized(&self) -> Result<bool, StoreError>;

    /// Initializes the Raft cluster with the given node configuration.
    async fn initialize(&self, nodes: HashMap<u64, Node>) -> Result<(), StoreError>;
}
