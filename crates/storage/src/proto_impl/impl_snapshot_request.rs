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
use crate::pb::raft::snapshot_request::Payload;
use crate::protobuf as pb;

impl pb::raft::SnapshotRequest {
    pub fn into_meta(self) -> Option<pb::raft::SnapshotRequestMeta> {
        let p = self.payload?;
        match p {
            Payload::Meta(meta) => Some(meta),
            Payload::Chunk(_) => None,
        }
    }

    pub fn into_data_chunk(self) -> Option<Vec<u8>> {
        let p = self.payload?;
        match p {
            Payload::Meta(_) => None,
            Payload::Chunk(chunk) => Some(chunk),
        }
    }
}
