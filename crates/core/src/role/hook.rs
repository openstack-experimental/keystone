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
//! # Role provider hooks for inter-provider events.

use crate::events::ProviderHooks;
use crate::keystone::ServiceState;
use async_trait::async_trait;
use openstack_keystone_core_types::events::Event;

/// Hook that subscribes the role provider to inter-provider events.
pub struct RoleHook {
    #[allow(unused)]
    state: ServiceState,
}

impl RoleHook {
    /// Create a new hook bound to the given service state.
    pub fn new(state: ServiceState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl ProviderHooks for RoleHook {
    async fn on_event(&self, _event: &Event) {}
}
