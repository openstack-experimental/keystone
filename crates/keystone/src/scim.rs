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
//! # SCIM ingress sub-router (ADR 0021)
//!
//! Mounted independently of `/v3`/`/v4` at `/SCIM/v2` per ADR 0021 §4
//! (Sub-Router Isolation): only handlers nested here use the
//! [`ApiKeyAuth`] extractor to accept API-Key bearer tokens. Core OpenStack
//! endpoints never use this extractor and therefore reject API keys
//! outright, satisfying the isolation requirement structurally rather than
//! via a path allowlist.
//!
//! SCIM resource endpoints (Users, Groups per RFC 7644) are out of scope
//! for ADR 0021, which specifies only the authentication ingress adapter.
//! `whoami` exists to prove the ingress pipeline end-to-end.
use axum::{
    Json, Router,
    extract::Path,
    middleware,
    routing::{get, post},
};
use serde::Serialize;

use openstack_keystone_core::api::api_key_auth::ApiKeyAuth;
use openstack_keystone_core::keystone::ServiceState;

mod bulk;
mod content_type;
mod discovery;
pub mod error;
pub mod etag;
mod extract;
pub mod filter;
mod group;
mod location;
pub mod patch;
pub mod types;
mod user;

/// Diagnostic response describing the resolved ephemeral security context.
#[derive(Serialize)]
struct WhoAmI {
    user_id: String,
    scope: String,
}

async fn whoami(Path(_domain_id): Path<String>, ApiKeyAuth(vsc): ApiKeyAuth) -> Json<WhoAmI> {
    let ctx = vsc.inner();
    Json(WhoAmI {
        user_id: ctx.principal().get_user_id(),
        scope: ctx
            .authorization()
            .map(|authz| format!("{:?}", authz.scope))
            .unwrap_or_else(|| "unscoped".to_string()),
    })
}

/// SCIM ingress sub-router, nested at `/SCIM/v2` in the main binary.
pub fn router() -> Router<ServiceState> {
    Router::new()
        .route("/{domain_id}/whoami", get(whoami))
        .route("/{domain_id}/Bulk", post(bulk::bulk))
        .route("/{domain_id}/Me", get(bulk::me))
        .nest("/{domain_id}/Users", user::router())
        .nest("/{domain_id}/Groups", group::router())
        .nest("/{domain_id}", discovery::router())
        .route_layer(middleware::from_fn(content_type::enforce_scim_content_type))
}
