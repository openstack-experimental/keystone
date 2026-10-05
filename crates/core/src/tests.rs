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
//! # Test related functionality
//!
//! Compiled both under `#[cfg(test)]` and the `mock` feature so downstream
//! driver crates can reuse `get_mocked_state`. `clippy.toml`'s
//! `allow-unwrap-in-tests` only covers `#[cfg(test)]` builds, so the
//! `unwrap`/`expect` allowances are restated here for the `mock`-feature build.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::sync::Arc;

use sea_orm::DatabaseConnection;

use cadf::AuditDispatcher;
use openstack_keystone_config::{Config, ConfigManager};

use crate::keystone::{Service, ServiceState};
use crate::policy::MockPolicy;
use crate::provider::{Provider, ProviderBuilder};

pub async fn get_mocked_state(
    config: Option<Config>,
    provider_builder: Option<ProviderBuilder>,
) -> ServiceState {
    Arc::new(
        Service::new(
            ConfigManager::not_watched(config.unwrap_or_default()),
            DatabaseConnection::default(),
            provider_builder
                .unwrap_or(Provider::mocked_builder())
                .build()
                .unwrap(),
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    )
}

/// A `ValidatedSecurityContext` for a password-authenticated user, for tests
/// that exercise the audited (fail-closed) path of a provider.
pub fn test_vsc() -> crate::auth::ValidatedSecurityContext {
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, IdentityInfo, PrincipalInfo, SecurityContext,
        UserIdentityInfoBuilder,
    };
    let user = UserIdentityInfoBuilder::default()
        .user_id("test-user-id".to_string())
        .build()
        .unwrap();
    let sc = SecurityContext::test_build()
        .authentication_context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(user),
        })
        .build();
    crate::auth::ValidatedSecurityContext::test_new(sc)
}

/// An [`AuditHook`](crate::events::AuditHook) that records every
/// `(operation, payload, outcome)` it sees and can be told to refuse the
/// pre-audit `Attempt`, which makes the audited operation fail closed.
#[derive(Default)]
pub struct RecordingAuditHook {
    seen: std::sync::Mutex<Vec<(String, String, String)>>,
    refuse_attempt: std::sync::atomic::AtomicBool,
}

impl RecordingAuditHook {
    /// A hook that accepts every event.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A hook whose pre-audit call fails.
    pub fn refusing() -> Arc<Self> {
        let hook = Self::default();
        hook.refuse_attempt
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Arc::new(hook)
    }

    /// The recorded `(operation, payload, outcome)` triples, `Debug`-formatted.
    pub fn seen(&self) -> Vec<(String, String, String)> {
        self.seen.lock().unwrap().clone()
    }

    /// The recorded outcomes only, e.g. `["Attempt", "Success"]`.
    pub fn outcomes(&self) -> Vec<String> {
        self.seen().into_iter().map(|(_, _, o)| o).collect()
    }
}

#[async_trait::async_trait]
impl crate::events::AuditHook for RecordingAuditHook {
    async fn on_auditable_event(
        &self,
        _ctx: &crate::auth::ValidatedSecurityContext,
        event: &openstack_keystone_core_types::events::Event,
        outcome: &crate::events::AuditOutcome,
    ) -> Result<(), crate::events::AuditDispatchError> {
        if self
            .refuse_attempt
            .load(std::sync::atomic::Ordering::SeqCst)
            && matches!(outcome, crate::events::AuditOutcome::Attempt)
        {
            return Err(crate::events::AuditDispatchError::HookFailed {
                description: "refused by test hook",
            });
        }
        self.seen.lock().unwrap().push((
            format!("{:?}", event.operation),
            format!("{:?}", event.payload),
            format!("{outcome:?}"),
        ));
        Ok(())
    }
}
