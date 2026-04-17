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

/// Store command.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum StoreCommand {
    /// Store mutation transaction.
    Transaction(Vec<Mutation>),
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

    /// Set the value for the key in the store.
    Set {
        /// The key to set.
        key: Vec<u8>,

        /// The `keyspace` of the key.
        keyspace: String,

        /// The value to set.
        #[serde(with = "serde_bytes")]
        value: Vec<u8>,
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

    pub fn set<K, V, S>(key: K, value: V, keyspace: Option<S>) -> Result<Self, StoreError>
    where
        K: Into<Vec<u8>>,
        V: Serialize,
        S: Into<String>,
    {
        Ok(Self::Set {
            key: key.into(),
            value: rmp_serde::to_vec(&value)?,
            keyspace: keyspace.map(Into::into).unwrap_or("data".into()),
        })
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
        let cmd = StoreCommand::Transaction(vec![mutation]);

        let packed = cmd.pack().unwrap();
        let unpacked = StoreCommand::unpack(&packed).unwrap();
        assert_eq!(cmd, unpacked);
    }

    #[test]
    fn test_set_command() {
        let mutation = Mutation::set("foo", "value", Some("bar")).unwrap();
        let cmd = StoreCommand::Transaction(vec![mutation]);
        let packed = cmd.pack().unwrap();
        let unpacked = StoreCommand::unpack(&packed).unwrap();
        assert_eq!(cmd, unpacked);
        if let StoreCommand::Transaction(data) = unpacked
            && let Some(mutation) = data.first()
            && let Mutation::Set { value, .. } = mutation
        {
            assert_eq!(value, &rmp_serde::to_vec("value").unwrap());
        } else {
            panic!("should be the set command");
        }
    }
}
