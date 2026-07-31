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
//! Raft-backed SCIM realm reads (ADR 0024). `create_realm` requires an
//! existing federation IdP (checked live against `get_identity_provider`),
//! so the realm exercised here is seeded once in `seed.rs`, not per-VU --
//! there is also no realm-delete endpoint (only per-resource purge), so a
//! per-VU create/delete cycle isn't possible for this domain.

use goose::prelude::*;
use serde_json::json;
use std::sync::OnceLock;

use crate::Session;

const DEFAULT_DOMAIN_ID: &str = "default";

static REALM_PROVIDER_ID: OnceLock<String> = OnceLock::new();

/// Call once before `GooseAttack::execute()` to share the seeded SCIM realm
/// with all virtual users.
pub fn set_realm_provider_id(id: String) {
    REALM_PROVIDER_ID.set(id).ok();
}

/// List SCIM realms in the default domain.
pub async fn list(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let path = format!("/v4/scim_realms?domain_id={DEFAULT_DOMAIN_ID}");
    let req = user
        .get_request_builder(&GooseMethod::Get, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("GET /v4/scim_realms")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// Show the seeded SCIM realm.
pub async fn show(user: &mut GooseUser) -> TransactionResult {
    let Some(provider_id) = REALM_PROVIDER_ID.get() else {
        return Ok(());
    };
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let path = format!("/v4/scim_realms/{DEFAULT_DOMAIN_ID}/{provider_id}");
    let req = user
        .get_request_builder(&GooseMethod::Get, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("GET /v4/scim_realms/:domain_id/:provider_id")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// Idempotently rewrite the seeded realm's `display_name` (raft write path).
pub async fn update(user: &mut GooseUser) -> TransactionResult {
    let Some(provider_id) = REALM_PROVIDER_ID.get() else {
        return Ok(());
    };
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let body = json!({
        "scim_realm": {
            "display_name": "Loadtest SCIM realm"
        }
    });
    let path = format!("/v4/scim_realms/{DEFAULT_DOMAIN_ID}/{provider_id}");
    let req = user
        .get_request_builder(&GooseMethod::Put, &path)?
        .header("x-auth-token", &token)
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("PUT /v4/scim_realms/:domain_id/:provider_id")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}
