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
//! # Common functionality
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::Client;
use tokio::sync::RwLock;

pub mod password_hashing;

/// HTTP Client pool trait.
#[async_trait]
pub trait HttpClientProvider: Send + Sync {
    /// Get established [Client] by the name.
    async fn get_client(&self, name: &str) -> Option<Arc<Client>>;
    /// Pub established [Client] into the connection pool.
    async fn put_client(&self, name: &str, client: Arc<Client>);
}

/// Http client pool.
///
/// NOTE: Simply placing the RwLock<HashMap<String, Arc<Client>>> into the
/// providers immediately explodes the compilation time. To deal with it is
/// moved out into a separate structure making it at the same time reusable.
#[derive(Default)]
pub struct HttpClientPool {
    pub inner: RwLock<HashMap<String, Arc<Client>>>,
}

#[async_trait]
impl HttpClientProvider for HttpClientPool {
    async fn get_client(&self, name: &str) -> Option<Arc<Client>> {
        let read_guard = self.inner.read().await;
        read_guard.get(name).cloned()
    }

    async fn put_client(&self, name: &str, client: Arc<Client>) {
        let mut write_guard = self.inner.write().await;
        write_guard.insert(name.to_string(), client);
    }
}
