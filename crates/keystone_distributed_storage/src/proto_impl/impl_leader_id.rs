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
//! # Implement [`RaftLeaderId`] for protobuf defined LeaderId, so that it can be used in OpenRaft

use std::cmp::Ordering;
use std::fmt;

use openraft::vote::LeaderIdCompare;
use openraft::vote::RaftLeaderId;

use crate::TypeConfig;
use crate::protobuf as pb;

/// Implements PartialOrd for LeaderId to enforce the standard Raft behavior of
/// at most one leader per term.
///
/// In standard Raft, each term can have at most one leader. This is enforced by
/// making leader IDs with the same term incomparable (returning None), unless
/// they refer to the same node.
///
/// This differs from the [`PartialOrd`] default implementation which would
/// allow multiple leaders in the same term by comparing node IDs.
impl PartialOrd for pb::raft::LeaderId {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        LeaderIdCompare::std(self, other)
    }
}

impl PartialEq<u64> for pb::raft::LeaderId {
    fn eq(&self, _other: &u64) -> bool {
        false
    }
}

impl PartialOrd<u64> for pb::raft::LeaderId {
    fn partial_cmp(&self, other: &u64) -> Option<Ordering> {
        self.term.partial_cmp(other)
    }
}

impl fmt::Display for pb::raft::LeaderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "T{}-N{}", self.term, self.node_id)
    }
}

impl RaftLeaderId<TypeConfig> for pb::raft::LeaderId {
    type Committed = u64;

    fn new(term: u64, node_id: u64) -> Self {
        Self { term, node_id }
    }

    fn term(&self) -> u64 {
        self.term
    }

    fn node_id(&self) -> &u64 {
        &self.node_id
    }

    fn to_committed(&self) -> Self::Committed {
        self.term
    }
}
