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
use crate::types::ClientWriteResponse;
use crate::{StoreError, pb};

impl TryFrom<pb::raft::AdminResponse> for ClientWriteResponse {
    type Error = StoreError;
    fn try_from(r: pb::raft::AdminResponse) -> Result<Self, Self::Error> {
        Ok(ClientWriteResponse {
            log_id: r
                .log_id
                .ok_or_else(|| StoreError::RaftMissingParameter("AdminResponse.LogId".into()))?
                .into(),
            data: r.data.unwrap_or_default(),
            membership: r.membership.map(|mem| mem.try_into()).transpose()?,
        })
    }
}

impl From<ClientWriteResponse> for pb::raft::AdminResponse {
    fn from(r: ClientWriteResponse) -> Self {
        pb::raft::AdminResponse {
            log_id: Some(r.log_id.into()),
            data: Some(r.data),
            membership: r.membership.map(|mem| mem.into()),
        }
    }
}
