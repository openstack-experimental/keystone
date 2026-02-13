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
use crate::types::AppendEntriesRequest;
use crate::{StoreError, pb};

impl TryFrom<pb::raft::AppendEntriesRequest> for AppendEntriesRequest {
    type Error = StoreError;
    fn try_from(proto_req: pb::raft::AppendEntriesRequest) -> Result<Self, Self::Error> {
        Ok(AppendEntriesRequest {
            vote: proto_req
                .vote
                .ok_or_else(|| StoreError::RaftMissingParameter("VoteResponse.Vote".into()))?,
            prev_log_id: proto_req.prev_log_id.map(|log_id| log_id.into()),
            entries: proto_req.entries,
            leader_commit: proto_req.leader_commit.map(|log_id| log_id.into()),
        })
    }
}

impl From<AppendEntriesRequest> for pb::raft::AppendEntriesRequest {
    fn from(value: AppendEntriesRequest) -> Self {
        pb::raft::AppendEntriesRequest {
            vote: Some(value.vote),
            prev_log_id: value.prev_log_id.map(|log_id| log_id.into()),
            entries: value.entries,
            leader_commit: value.leader_commit.map(|log_id| log_id.into()),
        }
    }
}
