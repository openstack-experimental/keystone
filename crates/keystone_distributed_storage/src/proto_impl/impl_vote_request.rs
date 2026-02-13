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
use crate::pb;
use crate::types::VoteRequest;

impl From<VoteRequest> for pb::raft::VoteRequest {
    fn from(vote_req: VoteRequest) -> Self {
        pb::raft::VoteRequest {
            vote: Some(vote_req.vote),
            last_log_id: vote_req.last_log_id.map(|log_id| log_id.into()),
        }
    }
}

impl From<pb::raft::VoteRequest> for VoteRequest {
    fn from(proto_vote_req: pb::raft::VoteRequest) -> Self {
        let vote = proto_vote_req.vote.unwrap();
        let last_log_id = proto_vote_req.last_log_id.map(|log_id| log_id.into());
        VoteRequest::new(vote, last_log_id)
    }
}
