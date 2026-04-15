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

/// Store modification command.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum StoreCommand {
    /// Delete the entry from the store.
    Delete(DeleteCommand),
    /// Set the value for the key in the store.
    Set(SetCommand),
}

/// Command to delete the value from the store.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct DeleteCommand {
    /// Key to delete.
    pub key: String,

    /// Keyspace of the key.
    pub keyspace: String,
}

/// Command to set the value in the store.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct SetCommand {
    /// Key to set.
    pub key: String,

    /// Keyspace of the key.
    pub keyspace: String,

    /// Value to set.
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

impl StoreCommand {
    /// Pack the [StoreCommand] into the format safe for the Raft log.
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
        let cmd = StoreCommand::Delete(DeleteCommand {
            key: "foo".into(),
            keyspace: "bar".into(),
        });
        let packed = cmd.pack().unwrap();
        let unpacked = StoreCommand::unpack(&packed).unwrap();
        assert_eq!(cmd, unpacked);
    }

    #[test]
    fn test_set_command() {
        let cmd = StoreCommand::Set(SetCommand {
            key: "foo".into(),
            keyspace: "bar".into(),
            value: "value".as_bytes().to_vec(),
        });
        let packed = cmd.pack().unwrap();
        let unpacked = StoreCommand::unpack(&packed).unwrap();
        assert_eq!(cmd, unpacked);
        if let StoreCommand::Set(cmd) = unpacked {
            assert_eq!("value", str::from_utf8(&cmd.value).unwrap());
        } else {
            panic!("should be the set command");
        }
    }
}
