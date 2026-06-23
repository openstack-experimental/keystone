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
use crate::types::{Metadata, Nonce};

/// Re-export `Mutation` from storage-api crate.
pub use openstack_keystone_storage_api::Mutation;

/// Store command.
///
/// An operation to be performed on the storage. The data is transferred
/// encrypted over the wire since it is stored in the raft log files.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum StoreCommand {
    /// Store mutation transaction.
    Transaction(Vec<MutationInner>),
}

/// Inner representation of the store modification operation encrypting the data
/// for at-rest storage.
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
        /// The value to set.
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

        /// Nonce.
        nonce: Nonce,
    },

    /// Set the value for the key only if the key does not already exist.
    /// If the key exists, a CONFLICT violation is emitted and no write occurs.
    CreateIfAbsent {
        /// The value to set.
        #[serde(with = "serde_bytes")]
        cipher: Vec<u8>,

        /// The key to set.
        key: Vec<u8>,

        /// The `keyspace` of the key.
        keyspace: String,

        /// The resource metadata.
        metadata: Metadata,

        /// Nonce.
        nonce: Nonce,
    },

    /// Set the key in the index keyspace.
    SetIndex {
        /// The key to set.
        key: Vec<u8>,
    },
}

impl MutationInner {
    /// Convert the mutation operation into the Raft operation.
    ///
    /// Convert the mutation command into the raft operation encrypting the data
    /// for the at-rest encryption.
    ///
    /// # Parameters
    /// - `value`: The mutation to convert.
    /// - `nonce`: The encryption nonce.
    ///
    /// # Returns
    /// A `Result` containing the `MutationInner`, or a `StoreError`.
    pub fn convert(value: Mutation, nonce: Nonce) -> Result<MutationInner, StoreError> {
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
                // TODO: encrypt for at-rest
                cipher: value,
                nonce,
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
                // TODO: encrypt for at-rest
                cipher: value,
                nonce,
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

    #[test]
    fn test_delete_command() {
        let mutation = Mutation::remove("foo", Some("bar"), None);
        let cmd = StoreCommand::Transaction(vec![
            MutationInner::convert(mutation, Nonce::default()).unwrap(),
        ]);

        let packed = cmd.pack().unwrap();
        let unpacked = StoreCommand::unpack(&packed).unwrap();
        assert_eq!(cmd, unpacked);
    }

    #[test]
    fn test_delete_command_with_expected_revision() {
        let mutation = Mutation::remove("foo", Some("bar"), Some(42));
        let cmd = StoreCommand::Transaction(vec![
            MutationInner::convert(mutation, Nonce::default()).unwrap(),
        ]);

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
        let cmd = StoreCommand::Transaction(vec![
            MutationInner::convert(mutation, Nonce::default()).unwrap(),
        ]);

        let packed = cmd.pack().unwrap();
        let unpacked = StoreCommand::unpack(&packed).unwrap();
        assert_eq!(cmd, unpacked);
    }

    #[test]
    fn test_set_command() {
        let mutation =
            Mutation::set("foo", "value", Metadata::new(), Some("bar"), Some(3)).unwrap();
        let cmd = StoreCommand::Transaction(vec![
            MutationInner::convert(mutation, Nonce::default()).unwrap(),
        ]);
        let packed = cmd.pack().unwrap();
        let unpacked = StoreCommand::unpack(&packed).unwrap();
        assert_eq!(cmd, unpacked);
        if let StoreCommand::Transaction(data) = unpacked
            && let Some(mutation) = data.first()
            && let MutationInner::Set { cipher, .. } = mutation
        {
            assert_eq!(cipher, &rmp_serde::to_vec("value").unwrap());
        } else {
            panic!("should be the set command");
        }
    }

    #[test]
    fn test_set_index_command() {
        let mutation = Mutation::set_index("foo");
        let cmd = StoreCommand::Transaction(vec![
            MutationInner::convert(mutation, Nonce::default()).unwrap(),
        ]);
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
