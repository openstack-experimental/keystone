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
use std::fmt;

use openraft::vote::RaftVote;

use crate::TypeConfig;
use crate::pb;
use crate::types::LeaderId;

impl RaftVote<TypeConfig> for pb::raft::Vote {
    fn from_leader_id(leader_id: LeaderId, committed: bool) -> Self {
        pb::raft::Vote {
            leader_id: Some(leader_id),
            committed,
        }
    }

    fn leader_id(&self) -> &LeaderId {
        self.leader_id.as_ref().expect("Vote must have a leader_id")
    }

    fn is_committed(&self) -> bool {
        self.committed
    }
}

impl fmt::Display for pb::raft::Vote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<{}:{}>",
            self.leader_id(),
            if self.is_committed() { "Q" } else { "-" }
        )
    }
}
