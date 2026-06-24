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
//! # Store modification command

use serde::{Deserialize, Serialize};

use crate::StoreError;
use crate::types::Metadata;

/// Re-export `Mutation` from storage-api crate.
pub use openstack_keystone_storage_api::Mutation;

/// Store command.
///
/// An operation to be performed on the storage. The data is transferred
/// over the wire inside the Raft log entry; log entries are encrypted by
/// `log_encrypt` before being written to Fjall.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum StoreCommand {
    /// Store mutation transaction.
    Transaction(Vec<MutationInner>),
}

/// Inner representation of a store modification operation.
///
/// Carries plaintext value bytes for Set/CreateIfAbsent mutations; the state
/// machine re-encrypts them for at-rest storage via `state_encrypt` during
/// `apply`.  `tier` is the data-sensitivity classification (ADR §3) bound
/// cryptographically into the GCM Associated Data.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum MutationInner {
    /// Delete the entry from the store.
    Remove {
        /// The Key to delete.
        key: Vec<u8>,

        /// The `keyspace` of the key.
        keyspace: String,

        /// Expected revision for CAS-protected delete.
        expected_revision: Option<u64>,
    },

    /// Delete the entry from the index store.
    RemoveIndex {
        /// The Key to delete.
        key: Vec<u8>,
    },

    /// Set the value for the key in the store.
    Set {
        /// Plaintext serialized value bytes (encrypted by state machine on apply).
        #[serde(with = "serde_bytes")]
        cipher: Vec<u8>,

        /// Expected revision.
        expected_revision: Option<u64>,

        /// The key to set.
        key: Vec<u8>,

        /// The `keyspace` of the key.
        keyspace: String,

        /// The resource metadata.
        metadata: Metadata,

        /// Data sensitivity tier (ADR §3); bound into GCM AD on state_encrypt.
        tier: u8,
    },

    /// Set the value for the key only if the key does not already exist.
    /// If the key exists, a CONFLICT violation is emitted and no write occurs.
    CreateIfAbsent {
        /// Plaintext serialized value bytes (encrypted by state machine on apply).
        #[serde(with = "serde_bytes")]
        cipher: Vec<u8>,

        /// The key to set.
        key: Vec<u8>,

        /// The `keyspace` of the key.
        keyspace: String,

        /// The resource metadata.
        metadata: Metadata,

        /// Data sensitivity tier (ADR §3); bound into GCM AD on state_encrypt.
        tier: u8,
    },

    /// Set the key in the index keyspace.
    SetIndex {
        /// The key to set.
        key: Vec<u8>,
    },

    /// Clear the quarantine state for a keyspace partition.
    ///
    /// Removes the `_meta:quarantine:<partition>` persistence marker from Fjall
    /// and clears the in-memory `QuarantineTracker` entry so the partition
    /// becomes accessible again.  Propagated via Raft so all nodes are cleared.
    ClearQuarantine {
        /// The keyspace partition to un-quarantine (e.g. `"data"`).
        partition: String,
    },
}

impl MutationInner {
    /// Convert a public [`Mutation`] into the internal [`MutationInner`]
    /// representation.
    ///
    /// All `Set` and `CreateIfAbsent` mutations default to
    /// `DataTier::Internal` (tier byte = 1).  Callers that need a different
    /// tier must construct `MutationInner` directly.
    pub fn convert(value: Mutation) -> Result<MutationInner, StoreError> {
        Ok(match value {
            Mutation::Remove {
                key,
                keyspace,
                expected_revision,
            } => MutationInner::Remove {
                key,
                keyspace,
                expected_revision,
            },
            Mutation::RemoveIndex { key } => MutationInner::RemoveIndex { key },
            Mutation::Set {
                key,
                keyspace,
                value,
                metadata,
                expected_revision,
            } => MutationInner::Set {
                key,
                keyspace,
                metadata,
                cipher: value,
                tier: openstack_keystone_storage_api::DataTier::Internal as u8,
                expected_revision,
            },
            Mutation::CreateIfAbsent {
                key,
                keyspace,
                value,
                metadata,
            } => MutationInner::CreateIfAbsent {
                key,
                keyspace,
                metadata,
                cipher: value,
                tier: openstack_keystone_storage_api::DataTier::Internal as u8,
            },
            Mutation::SetIndex { key } => MutationInner::SetIndex { key },
        })
    }
}

impl StoreCommand {
    /// Pack the [`StoreCommand`] into the format safe for the Raft log.
    ///
    /// Serialize the data into the bytes using the MsgPack format.
    ///
    /// # Returns
    /// A `Result` containing the serialized bytes, or a `StoreError`.
    pub fn pack(&self) -> Result<Vec<u8>, StoreError> {
        Ok(rmp_serde::to_vec(self)?)
    }

    /// Restore the [StoreCommand] from the log safe data format.
    ///
    /// Unpack the [StoreCommand] from the bytes array.
    ///
    /// # Parameters
    /// - `value`: The binary data.
    ///
    /// # Returns
    /// A `Result` containing the `StoreCommand`, or a `StoreError`.
    pub fn unpack(value: &[u8]) -> Result<StoreCommand, StoreError> {
        Ok(rmp_serde::from_slice(value)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Metadata;

    #[test]
    fn test_delete_command() {
        let mutation = Mutation::remove("foo", Some("bar"), None);
        let cmd = StoreCommand::Transaction(vec![MutationInner::convert(mutation).unwrap()]);

        let packed = cmd.pack().unwrap();
        let unpacked = StoreCommand::unpack(&packed).unwrap();
        assert_eq!(cmd, unpacked);
    }

    #[test]
    fn test_delete_command_with_expected_revision() {
        let mutation = Mutation::remove("foo", Some("bar"), Some(42));
        let cmd = StoreCommand::Transaction(vec![MutationInner::convert(mutation).unwrap()]);

        let packed = cmd.pack().unwrap();
        let unpacked = StoreCommand::unpack(&packed).unwrap();
        assert_eq!(cmd, unpacked);
        if let StoreCommand::Transaction(data) = &unpacked
            && let Some(MutationInner::Remove {
                expected_revision, ..
            }) = data.first()
        {
            assert_eq!(*expected_revision, Some(42));
        } else {
            panic!("expected Remove mutation with expected_revision");
        }
    }

    #[test]
    fn test_delete_index_command() {
        let mutation = Mutation::remove_index("foo");
        let cmd = StoreCommand::Transaction(vec![MutationInner::convert(mutation).unwrap()]);

        let packed = cmd.pack().unwrap();
        let unpacked = StoreCommand::unpack(&packed).unwrap();
        assert_eq!(cmd, unpacked);
    }

    #[test]
    fn test_set_command() {
        let mutation =
            Mutation::set("foo", "value", Metadata::new(), Some("bar"), Some(3)).unwrap();
        let cmd = StoreCommand::Transaction(vec![MutationInner::convert(mutation).unwrap()]);
        let packed = cmd.pack().unwrap();
        let unpacked = StoreCommand::unpack(&packed).unwrap();
        assert_eq!(cmd, unpacked);
        if let StoreCommand::Transaction(data) = unpacked
            && let Some(mutation) = data.first()
            && let MutationInner::Set { cipher, tier, .. } = mutation
        {
            assert_eq!(cipher, &rmp_serde::to_vec("value").unwrap());
            assert_eq!(*tier, 1u8); // DataTier::Internal
        } else {
            panic!("should be the set command");
        }
    }

    #[test]
    fn test_set_index_command() {
        let mutation = Mutation::set_index("foo");
        let cmd = StoreCommand::Transaction(vec![MutationInner::convert(mutation).unwrap()]);
        let packed = cmd.pack().unwrap();
        let unpacked = StoreCommand::unpack(&packed).unwrap();
        assert_eq!(cmd, unpacked);
        if let StoreCommand::Transaction(data) = unpacked
            && let Some(mutation) = data.first()
            && let MutationInner::SetIndex { key } = mutation
        {
            assert_eq!("foo".as_bytes(), key);
        } else {
            panic!("should be the set_index command");
        }
    }
}
