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
//! # Limit provider hooks for inter-provider events.

use async_trait::async_trait;
use tracing::error;

use openstack_keystone_core_types::events::{Event, EventPayload, Operation};

use crate::auth::ExecutionContext;
use crate::events::ProviderHooks;
use crate::keystone::ServiceState;

/// Hook that removes the limits of the deleted projects and domains.
pub struct LimitHook {
    state: ServiceState,
}

impl LimitHook {
    /// Create a new hook bound to the given service state.
    pub fn new(state: ServiceState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl ProviderHooks for LimitHook {
    async fn on_event(&self, event: &Event) {
        if !matches!(event.operation, Operation::Delete) {
            return;
        }
        let exec = ExecutionContext::internal(&self.state);
        let provider = self.state.provider.get_limit_provider();
        let res = match &event.payload {
            EventPayload::Project { id } => provider.delete_limits_by_project(&exec, id).await,
            EventPayload::Domain { id } => provider.delete_limits_by_domain(&exec, id).await,
            _ => return,
        };
        if let Err(err) = res {
            error!("failed to cleanup limits of the deleted resource: {err}");
        }
    }
}
