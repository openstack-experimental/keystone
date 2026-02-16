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
use crate::types::VoteResponse;
use crate::{StoreError, pb};

impl From<VoteResponse> for pb::raft::VoteResponse {
    fn from(vote_resp: VoteResponse) -> Self {
        pb::raft::VoteResponse {
            vote: Some(vote_resp.vote),
            vote_granted: vote_resp.vote_granted,
            last_log_id: vote_resp.last_log_id.map(|log_id| log_id.into()),
        }
    }
}

impl TryFrom<pb::raft::VoteResponse> for VoteResponse {
    type Error = StoreError;
    fn try_from(proto_vote_resp: pb::raft::VoteResponse) -> Result<Self, Self::Error> {
        let vote = proto_vote_resp
            .vote
            .ok_or_else(|| StoreError::RaftMissingParameter("VoteResponse.Vote".into()))?;
        let last_log_id = proto_vote_resp.last_log_id.map(|log_id| log_id.into());
        Ok(VoteResponse::new(
            vote,
            last_log_id,
            proto_vote_resp.vote_granted,
        ))
    }
}
