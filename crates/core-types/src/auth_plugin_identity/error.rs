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
use thiserror::Error;

/// `(plugin_name, external_id) -> user_id` identity-binding index provider
/// error (ADR 0025 §4/§6.B/§6.C).
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum AuthPluginIdentityProviderError {
    /// Driver error.
    #[error("backend driver error: {source}")]
    Driver {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Raft storage is not available.
    #[error("raft storage is not available in the auth_plugin_identity provider")]
    RaftNotAvailable,

    /// Raft storage error.
    #[error("raft storage error in the auth_plugin_identity provider: {source}")]
    RaftStoreError {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Unsupported driver.
    #[error("unsupported driver `{0}` for the auth_plugin_identity provider")]
    UnsupportedDriver(String),
}

impl AuthPluginIdentityProviderError {
    /// Wrap a raft storage error.
    pub fn raft<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::RaftStoreError {
            source: Box::new(source),
        }
    }
}
