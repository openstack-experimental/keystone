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
use serde::Deserialize;
use std::path::PathBuf;

/// Raft cluster configuration.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct DistributedStorageConfiguration {
    /// Cluster address.
    pub cluster_addr: String,

    /// Node id.
    pub node_id: u64,

    /// List of cluster nodes.
    #[serde(default)]
    pub nodes: Vec<ClusterNode>,

    /// Path to the storage
    pub path: PathBuf,
}

/// Raft cluster node.
#[derive(Debug, Deserialize, Clone)]
pub struct ClusterNode {
    /// Node address.
    pub addr: String,
    /// Node ID.
    pub id: u64,
}
