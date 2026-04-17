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

/// Store command.
///
/// An operation to be performed on the storage. The data is transferred encrypted over the wire
/// since it is stored in the raft log files.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum StoreCommand {
    /// Store mutation transaction.
    Transaction(Vec<MutationInner>),
}

/// Inner representation of the store modification operation encrypting the data for at-rest
/// storage.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum MutationInner {
    /// Delete the entry from the store.
    Remove {
        /// The Key to delete.
        key: Vec<u8>,

        /// The `keyspace` of the key.
        keyspace: String,
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

    /// Set the key in the index keyspace.
    SetIndex {
        /// The key to set.
        key: Vec<u8>,
    },
}

impl MutationInner {
    /// Convert the mutation operation into the Raft operation.
    ///
    /// Convert the mutation command into the raft operation encrypting the data for the at-rest
    /// encryption.
    pub fn convert(value: Mutation, nonce: Nonce) -> Result<MutationInner, StoreError> {
        Ok(match value {
            Mutation::Remove { key, keyspace } => MutationInner::Remove { key, keyspace },
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
            Mutation::SetIndex { key } => MutationInner::SetIndex { key },
        })
    }
}

/// Store modification operation.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum Mutation {
    /// Delete the entry from the store.
    Remove {
        /// The Key to delete.
        key: Vec<u8>,

        /// The `keyspace` of the key.
        keyspace: String,
    },

    /// Delete the entry from the store.
    RemoveIndex {
        /// The Key to delete.
        key: Vec<u8>,
    },

    /// Set the value for the key in the store.
    Set {
        /// Expected revision.
        expected_revision: Option<u64>,

        /// The key to set.
        key: Vec<u8>,

        /// The `keyspace` of the key.
        keyspace: String,

        /// The resource metadata.
        metadata: Metadata,

        /// The value to set.
        #[serde(with = "serde_bytes")]
        value: Vec<u8>,
    },

    /// Set the value for the key in the store.
    SetIndex {
        /// The key to set.
        key: Vec<u8>,
    },
}

impl Mutation {
    pub fn remove<K, S>(key: K, keyspace: Option<S>) -> Result<Self, StoreError>
    where
        K: Into<Vec<u8>>,
        S: Into<String>,
    {
        Ok(Self::Remove {
            key: key.into(),
            keyspace: keyspace.map(Into::into).unwrap_or("data".into()),
        })
    }

    pub fn remove_index<K>(key: K) -> Result<Self, StoreError>
    where
        K: Into<Vec<u8>>,
    {
        Ok(Self::RemoveIndex { key: key.into() })
    }

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

    pub fn set_index<K>(key: K) -> Result<Self, StoreError>
    where
        K: Into<Vec<u8>>,
    {
        Ok(Self::SetIndex { key: key.into() })
    }
}

impl StoreCommand {
    /// Pack the [`StoreCommand`] into the format safe for the Raft log.
    ///
    /// Serialize the data into the bytes using the MsgPack format.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Bytes vector.
    /// * `Err(StoreError)` - Error.
    pub fn pack(&self) -> Result<Vec<u8>, StoreError> {
        Ok(rmp_serde::to_vec(self)?)
    }

    /// Restore the [StoreCommand] from the log safe data format.
    ///
    /// Unpack the [StoreCommand] from the bytes array.
    ///
    /// # Arguments
    /// * `value` - The binary data.
    ///
    /// # Returns
    /// * `Ok(StoreCommand)` - Success response.
    /// * `Err(StoreError)` - Error if the operation fails.
    pub fn unpack(value: &[u8]) -> Result<StoreCommand, StoreError> {
        Ok(rmp_serde::from_slice(value)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delete_command() {
        let mutation = Mutation::remove("foo", Some("bar")).unwrap();
        let cmd = StoreCommand::Transaction(vec![
            MutationInner::convert(mutation, Nonce::default()).unwrap(),
        ]);

        let packed = cmd.pack().unwrap();
        let unpacked = StoreCommand::unpack(&packed).unwrap();
        assert_eq!(cmd, unpacked);
    }

    #[test]
    fn test_delete_index_command() {
        let mutation = Mutation::remove_index("foo").unwrap();
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
        let mutation = Mutation::set_index("foo").unwrap();
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
