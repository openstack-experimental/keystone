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
//! # Dynamic plugin identity-binding index (ADR 0025 §4)
//!
//! `(plugin_name, external_id) -> user_id` namespace-scoped mapping backing
//! `provision_user`/`find_user` (§6.B/§6.C). Storage-agnostic: today backed
//! by a raft KV index (`openstack-keystone-dynamic-plugin-identity-driver-
//! raft`), decoupled from whichever `IdentityBackend` is configured so a
//! future non-raft driver can be added without touching identity storage.

mod error;

pub use error::*;
