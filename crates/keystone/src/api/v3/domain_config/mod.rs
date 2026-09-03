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
//! # Domain configuration API
//!
//! Per-domain overrides of the identity backend configuration, exposed under
//! `/v3/domains`:
//!
//! - `/{domain_id}/config` — whole-configuration CRUD;
//! - `/{domain_id}/config/{group}` — one group;
//! - `/{domain_id}/config/{group}/{option}` — one option;
//! - `/config/default`, `/config/{group}/default`,
//!   `/config/{group}/{option}/default` — the global defaults a domain without
//!   its own configuration falls back to.
//!
//! The routes merge into the `domains` router (see the parent module). The
//! stored configuration is not yet consumed by identity-driver selection —
//! that is issue #960.

use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

mod create;
mod default;
mod delete;
mod group;
mod option;
mod show;
pub mod types;
mod update;

/// OpenApi specification for the domain configuration API.
#[derive(OpenApi)]
#[openapi(tags((
    name = "domain_config",
    description = "Per-domain identity backend configuration overrides."
)))]
pub struct ApiDoc;

pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(
            create::create,
            show::show,
            update::update,
            delete::remove
        ))
        .routes(routes!(group::show, group::update, group::remove))
        .routes(routes!(option::show, option::update, option::remove))
        .routes(routes!(default::show))
        .routes(routes!(default::show_group))
        .routes(routes!(default::show_option))
}

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    pub(crate) use http_body_util::BodyExt;
    pub(crate) use tower::ServiceExt;
    pub(crate) use tower_http::trace::TraceLayer;

    pub(crate) use openstack_keystone_core::domain_config::MockDomainConfigProvider;
    pub(crate) use openstack_keystone_core_types::domain_config::DomainConfig;

    pub(crate) use super::openapi_router;
    pub(crate) use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    pub(crate) use crate::provider::Provider;

    /// A `DomainConfig` from a request-shaped object (`{"ldap": {...}}`).
    pub(crate) fn config(body: serde_json::Value) -> DomainConfig {
        DomainConfig::from_value(body).expect("a valid domain configuration")
    }

    /// A `MockDomainConfigProvider` with no expectation set, for the
    /// forbidden/unauthorized paths that never reach the provider.
    pub(crate) fn no_backend_calls() -> MockDomainConfigProvider {
        MockDomainConfigProvider::default()
    }

    /// A mocked `ServiceState` whose domain-config provider is `mock` and
    /// whose policy enforcer allows or denies per `allowed`.
    pub(crate) async fn state(
        mock: MockDomainConfigProvider,
        allowed: bool,
    ) -> crate::keystone::ServiceState {
        get_mocked_state(
            Provider::mocked_builder().mock_domain_config(mock),
            allowed,
            None,
        )
        .await
    }
}
