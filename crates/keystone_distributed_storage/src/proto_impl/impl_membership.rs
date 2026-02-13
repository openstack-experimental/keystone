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
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use openraft::Membership;

use crate::TypeConfig;
use crate::pb;

impl From<pb::raft::Membership> for Membership<TypeConfig> {
    fn from(value: pb::raft::Membership) -> Self {
        let mut configs = vec![];
        for c in value.configs {
            let config: BTreeSet<u64> = c.node_ids.keys().copied().collect();
            configs.push(config);
        }
        let nodes = value.nodes;
        // TODO: do not unwrap()
        Membership::new(configs, nodes).unwrap()
    }
}

impl From<Membership<TypeConfig>> for pb::raft::Membership {
    fn from(value: Membership<TypeConfig>) -> Self {
        let mut configs = vec![];
        for c in value.get_joint_config() {
            let mut node_ids = BTreeMap::new();
            for nid in c.iter() {
                node_ids.insert(*nid, ());
            }
            configs.push(pb::raft::NodeIdSet { node_ids: node_ids });
        }
        let nodes = value.nodes().map(|(nid, n)| (*nid, n.clone())).collect();
        pb::raft::Membership { configs, nodes }
    }
}
