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

use async_trait::async_trait;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::StoreError;
use crate::pb::api::Response;
use crate::store_command::*;
use crate::types::*;

#[async_trait]
pub trait StorageApi {
    /// Checks whether a given key is present in the keyspace of the distributed store.
    async fn contains_key<K, S>(&self, key: K, keyspace: Option<S>) -> Result<bool, StoreError>
    where
        K: AsRef<[u8]> + Send,
        S: AsRef<str> + Send;

    /// Gets a value for a given key from the distributed store.
    async fn get_by_key<T, K, S>(
        &self,
        key: K,
        keyspace: Option<S>,
    ) -> Result<Option<StoreDataEnvelope<T>>, StoreError>
    where
        T: DeserializeOwned + Send,
        K: AsRef<[u8]> + Send,
        S: AsRef<str> + Send;

    /// List key value pairs by the prefix.
    async fn prefix<T, K, S>(
        &self,
        prefix: K,
        keyspace: Option<S>,
    ) -> Result<Vec<(String, StoreDataEnvelope<T>)>, StoreError>
    where
        T: DeserializeOwned + Send,
        K: AsRef<[u8]> + Send,
        S: AsRef<str> + Send;

    /// List index keys the prefix.
    async fn prefix_index<K>(&self, prefix: K) -> Result<Vec<String>, StoreError>
    where
        K: AsRef<[u8]> + Send;

    /// Deletes a value for a given key in the distributed store.
    async fn remove<K, S>(&self, key: K, keyspace: Option<S>) -> Result<Response, StoreError>
    where
        K: Into<Vec<u8>> + Send,
        S: Into<String> + Send;

    /// Deletes index key in the distributed store.
    async fn remove_index<K>(&self, key: K) -> Result<Response, StoreError>
    where
        K: Into<Vec<u8>> + Send;

    /// Sets a value for a given key in the distributed store.
    async fn set_value<K, V, S>(
        &self,
        key: K,
        value: StoreDataEnvelope<V>,
        keyspace: Option<S>,
        expected_revision: Option<u64>,
    ) -> Result<Response, StoreError>
    where
        K: Into<String> + Send,
        V: Serialize + Send,
        S: Into<String> + Send;

    /// Sets an index key in the distributed store.
    async fn set_index_key<K>(&self, key: K) -> Result<Response, StoreError>
    where
        K: Into<String> + Send;

    /// Mutation transaction
    ///
    /// # Arguments
    /// * `mutations` - List of mutations that must be applied as a single transaction.
    ///
    /// # Returns
    /// * `Ok(Response)` - Success response after the value is deleted
    /// * `Err(Status)` - Error status if the set operation fails
    async fn transaction(&self, mutations: Vec<Mutation>) -> Result<Response, StoreError>;
}
