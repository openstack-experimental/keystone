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
//! # Webauthn extension hook for inter-provider events.

use async_trait::async_trait;
use openstack_keystone_core::events::ProviderHooks;
use openstack_keystone_core_types::events::Event;

use crate::api::types::CombinedExtensionState;

/// Hook that subscribes the webauthn extension to inter-provider events.
pub struct WebauthnHook {
    #[allow(unused)]
    state: CombinedExtensionState,
}

impl WebauthnHook {
    /// Create a new hook bound to the given extension state.
    pub fn new(state: CombinedExtensionState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl ProviderHooks for WebauthnHook {
    async fn on_event(&self, _event: &Event) {}
}
