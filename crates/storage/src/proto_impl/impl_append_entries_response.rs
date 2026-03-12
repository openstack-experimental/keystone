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
use openraft::raft::StreamAppendError;

use crate::pb;
use crate::types::AppendEntriesResponse;
use crate::types::StreamAppendResult;

impl From<pb::raft::AppendEntriesResponse> for AppendEntriesResponse {
    fn from(r: pb::raft::AppendEntriesResponse) -> Self {
        if let Some(higher) = r.rejected_by {
            return AppendEntriesResponse::HigherVote(higher);
        }

        if r.conflict {
            return AppendEntriesResponse::Conflict;
        }

        if let Some(log_id) = r.last_log_id {
            AppendEntriesResponse::PartialSuccess(Some(log_id.into()))
        } else {
            AppendEntriesResponse::Success
        }
    }
}

impl From<AppendEntriesResponse> for pb::raft::AppendEntriesResponse {
    fn from(r: AppendEntriesResponse) -> Self {
        match r {
            AppendEntriesResponse::Success => pb::raft::AppendEntriesResponse {
                rejected_by: None,
                conflict: false,
                last_log_id: None,
            },
            AppendEntriesResponse::PartialSuccess(p) => pb::raft::AppendEntriesResponse {
                rejected_by: None,
                conflict: false,
                last_log_id: p.map(|log_id| log_id.into()),
            },
            AppendEntriesResponse::Conflict => pb::raft::AppendEntriesResponse {
                rejected_by: None,
                conflict: true,
                last_log_id: None,
            },
            AppendEntriesResponse::HigherVote(v) => pb::raft::AppendEntriesResponse {
                rejected_by: Some(v),
                conflict: false,
                last_log_id: None,
            },
        }
    }
}

impl From<StreamAppendResult> for pb::raft::AppendEntriesResponse {
    fn from(result: StreamAppendResult) -> Self {
        match result {
            Ok(Some(log_id)) => pb::raft::AppendEntriesResponse {
                rejected_by: None,
                conflict: false,
                last_log_id: Some(log_id.into()),
            },
            Ok(None) => pb::raft::AppendEntriesResponse {
                rejected_by: None,
                conflict: false,
                last_log_id: None,
            },
            Err(StreamAppendError::Conflict(log_id)) => pb::raft::AppendEntriesResponse {
                rejected_by: None,
                conflict: true,
                last_log_id: Some(log_id.into()),
            },
            Err(StreamAppendError::HigherVote(vote)) => pb::raft::AppendEntriesResponse {
                rejected_by: Some(vote),
                conflict: false,
                last_log_id: None,
            },
        }
    }
}
