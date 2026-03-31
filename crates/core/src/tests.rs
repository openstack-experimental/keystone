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

use openstack_keystone_audit::AuditDispatcher;
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
