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
use openraft::raft::{TransferLeaderError, TransferLeaderRequest, TransferLeaderResponse};

use crate::TypeConfig;
use crate::{StoreError, pb};

impl From<TransferLeaderRequest<TypeConfig>> for pb::raft::TransferLeaderRequest {
    fn from(req: TransferLeaderRequest<TypeConfig>) -> Self {
        pb::raft::TransferLeaderRequest {
            from_leader: Some(*req.from_leader()),
            to_node_id: *req.to_node_id(),
            last_log_id: req.last_log_id().map(|log_id| (*log_id).into()),
        }
    }
}

impl TryFrom<pb::raft::TransferLeaderRequest> for TransferLeaderRequest<TypeConfig> {
    type Error = StoreError;
    fn try_from(req: pb::raft::TransferLeaderRequest) -> Result<Self, Self::Error> {
        let from_leader = req.from_leader.ok_or_else(|| {
            StoreError::RaftMissingParameter("TransferLeaderRequest.from_leader".into())
        })?;
        Ok(TransferLeaderRequest::new(
            from_leader,
            req.to_node_id,
            req.last_log_id.map(Into::into),
        ))
    }
}

impl From<TransferLeaderResponse<TypeConfig>> for pb::raft::TransferLeaderResponse {
    fn from(resp: TransferLeaderResponse<TypeConfig>) -> Self {
        use pb::raft::transfer_leader_response::Rejection;
        let rejection = match resp {
            Ok(()) => None,
            Err(TransferLeaderError::VoteChanged { expected, actual }) => Some(
                Rejection::VoteChanged(pb::raft::TransferLeaderVoteChanged {
                    expected: Some(expected),
                    actual: Some(actual),
                }),
            ),
            Err(TransferLeaderError::LogNotFlushed { expected, actual }) => Some(
                Rejection::LogNotFlushed(pb::raft::TransferLeaderLogNotFlushed {
                    expected: expected.map(Into::into),
                    actual: actual.map(Into::into),
                }),
            ),
        };
        pb::raft::TransferLeaderResponse { rejection }
    }
}

impl TryFrom<pb::raft::TransferLeaderResponse> for TransferLeaderResponse<TypeConfig> {
    type Error = StoreError;
    fn try_from(resp: pb::raft::TransferLeaderResponse) -> Result<Self, Self::Error> {
        use pb::raft::transfer_leader_response::Rejection;
        let missing = |what: &str| StoreError::RaftMissingParameter(what.into());
        Ok(match resp.rejection {
            None => Ok(()),
            Some(Rejection::VoteChanged(r)) => Err(TransferLeaderError::VoteChanged {
                expected: r
                    .expected
                    .ok_or_else(|| missing("TransferLeaderVoteChanged.expected"))?,
                actual: r
                    .actual
                    .ok_or_else(|| missing("TransferLeaderVoteChanged.actual"))?,
            }),
            Some(Rejection::LogNotFlushed(r)) => Err(TransferLeaderError::LogNotFlushed {
                expected: r.expected.map(Into::into),
                actual: r.actual.map(Into::into),
            }),
        })
    }
}
