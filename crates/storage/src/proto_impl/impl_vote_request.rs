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
use crate::types::VoteRequest;
use crate::{StoreError, pb};

impl From<VoteRequest> for pb::raft::VoteRequest {
    fn from(vote_req: VoteRequest) -> Self {
        pb::raft::VoteRequest {
            vote: Some(vote_req.vote),
            last_log_id: vote_req.last_log_id.map(|log_id| log_id.into()),
            leadership_transfer_from: vote_req.leadership_transfer_from,
        }
    }
}

impl TryFrom<pb::raft::VoteRequest> for VoteRequest {
    type Error = StoreError;
    fn try_from(proto_vote_req: pb::raft::VoteRequest) -> Result<Self, Self::Error> {
        let vote = proto_vote_req
            .vote
            .ok_or_else(|| StoreError::RaftMissingParameter("VoteResponse.Vote".into()))?;
        let last_log_id = proto_vote_req.last_log_id.map(|log_id| log_id.into());
        let mut req = VoteRequest::new(vote, last_log_id);
        req.leadership_transfer_from = proto_vote_req.leadership_transfer_from;
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leadership_transfer_from_round_trips() {
        let vote = pb::raft::Vote::default();
        let mut req = VoteRequest::new(vote, None);
        req.leadership_transfer_from = Some(vote);

        let decoded = VoteRequest::try_from(pb::raft::VoteRequest::from(req))
            .unwrap_or_else(|_| VoteRequest::new(vote, None));
        assert_eq!(decoded.leadership_transfer_from, Some(vote));

        let plain =
            VoteRequest::try_from(pb::raft::VoteRequest::from(VoteRequest::new(vote, None)))
                .unwrap_or_else(|_| unreachable!());
        assert_eq!(plain.leadership_transfer_from, None);
    }
}
