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
use crate::types::*;

/// Raft cluster administrative operations.
///
/// # Responsibilities
/// - Manages the Raft cluster
///
/// # Protocol Safety
/// This service implements the client-facing API and should validate all inputs
/// before processing them through the Raft consensus protocol.
pub struct ClusterAdminService {
    /// The Raft node instance for consensus operations.
    pub(crate) raft_node: Raft,
}

impl ClusterAdminService {
    /// Creates a new instance of the API service.
    ///
    /// # Arguments
    /// * `raft_node` - The Raft node instance this service will use.
    pub fn new(raft_node: Raft) -> Self {
        Self { raft_node }
    }
}
