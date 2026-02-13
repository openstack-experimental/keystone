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

use openraft::EntryPayload;
use openraft::Membership;
use openraft::alias::LogIdOf;
use openraft::entry::RaftEntry;
use openraft::entry::RaftPayload;

use crate::TypeConfig;
use crate::protobuf as pb;

impl fmt::Display for pb::raft::Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Entry{{term={},index={}}}", self.term, self.index)
    }
}

impl RaftPayload<TypeConfig> for pb::raft::Entry {
    fn get_membership(&self) -> Option<Membership<TypeConfig>> {
        // NOTE: Converting the membership is fallible. This interface does not allow us to handle
        // it properly, so the conversion error is treated as `None`.
        self.membership
            .clone()
            .map(TryInto::try_into)
            .transpose()
            .unwrap_or(None)
    }
}

impl RaftEntry<TypeConfig> for pb::raft::Entry {
    fn new(log_id: LogIdOf<TypeConfig>, payload: EntryPayload<TypeConfig>) -> Self {
        let mut app_data = None;
        let mut membership = None;
        match payload {
            EntryPayload::Blank => {}
            EntryPayload::Normal(data) => app_data = Some(data),
            EntryPayload::Membership(m) => membership = Some(m.into()),
        }

        Self {
            term: log_id.leader_id,
            index: log_id.index,
            app_data,
            membership,
        }
    }

    fn log_id_parts(&self) -> (&u64, u64) {
        (&self.term, self.index)
    }

    fn set_log_id(&mut self, new: LogIdOf<TypeConfig>) {
        self.term = new.leader_id;
        self.index = new.index;
    }
}
