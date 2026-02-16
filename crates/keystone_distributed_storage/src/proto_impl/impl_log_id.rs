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
use crate::types::LogId;

impl From<LogId> for pb::raft::LogId {
    fn from(log_id: LogId) -> Self {
        pb::raft::LogId {
            term: *log_id.committed_leader_id(),
            index: log_id.index(),
        }
    }
}

impl From<pb::raft::LogId> for LogId {
    fn from(proto_log_id: pb::raft::LogId) -> Self {
        LogId::new(proto_log_id.term, proto_log_id.index)
    }
}
