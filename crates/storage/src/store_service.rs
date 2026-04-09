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
use std::sync::Arc;

use crate::types::StateMachineStore;
use crate::types::*;

/// External API service implementation providing key-value store operations.
/// This service handles client requests for getting and setting values in the
/// distributed store.
///
/// # Responsibilities
/// - Ensure consistency through Raft consensus
///
/// # Protocol Safety
/// This service implements the client-facing API and should validate all inputs
/// before processing them through the Raft consensus protocol.
pub struct StoreService {
    /// The Raft node instance for consensus operations.
    pub(crate) raft_node: Raft,
    /// The state machine store for direct reads.
    pub(crate) state_machine_store: Arc<StateMachineStore>,
}

impl StoreService {
    /// Creates a new instance of the API service.
    ///
    /// # Arguments
    /// * `raft_node` - The Raft node instance this service will use
    /// * `state_machine_store` - The state machine store for reading data
    pub fn new(raft_node: Raft, state_machine_store: Arc<StateMachineStore>) -> Self {
        Self {
            raft_node,
            state_machine_store,
        }
    }

    /// Sets a value for a given key in the distributed store.
    ///
    /// # Arguments
    /// * `key` - The key
    /// * `value` - The value to set for the key
    ///
    /// # Returns
    /// * `Ok(Response)` - Success response after the value is set
    /// * `Err(Status)` - Error status if the set operation fails
    pub async fn set_value<K, V>(&self, key: K, value: V) -> Result<ClientWriteResponse, StoreError>
    where
        K: Into<String>,
        V: Into<String>,
    {
        let res = self
            .raft_node
            .client_write(crate::pb::api::SetRequest {
                key: key.into(),
                value: value.into(),
            })
            .await?;
        Ok(res)
    }

    /// Gets a value for a given key from the distributed store.
    ///
    /// # Arguments
    /// * `key` - Contains the key to retrieve
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Success response containing the value as bytes
    /// * `Err(Status)` - Error status if the get operation fails
    pub async fn get_by_key<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<Vec<u8>>, StoreError> {
        let value = self
            .state_machine_store
            .data()
            .get(&key)?
            .map(|x| x.to_vec());
        Ok(value)
    }
}
