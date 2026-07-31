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
//! Simulates a real IdP-driven SCIM sync cycle against `/SCIM/v2` (ADR
//! 0024): unlike `v4::scim_realm` (which reads the realm as an admin, via
//! `x-auth-token`), this module authenticates as the machine identity an
//! IdP-side SCIM connector actually uses -- a `kscim_...` API Key bearer
//! token (ADR 0021) -- and drives the RFC 7644 lifecycle a sync connector
//! generates each cycle: provision (`POST`), reconcile (`GET` list/show),
//! attribute drift (`PATCH`), full-replace (`PUT`), offboarding (`DELETE`).
//!
//! Requires its own per-VU API Key (raft-backed, `provider_id` bound to the
//! seeded SCIM realm so `ScimRealmAuth`'s Realm Activation Gate passes) --
//! the shared admin token used everywhere else in this suite is rejected
//! outright by `/SCIM/v2` (ADR 0021 §4 Sub-Router Isolation only accepts API
//! Key bearer tokens there).

use chrono::{Duration, Utc};
use goose::prelude::*;
use serde_json::json;
use std::sync::OnceLock;
use uuid::Uuid;

const DEFAULT_DOMAIN_ID: &str = "default";
const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

static REALM_PROVIDER_ID: OnceLock<String> = OnceLock::new();

/// Call once before `GooseAttack::execute()` to share the seeded SCIM realm
/// this scenario's API Keys must bind to.
pub fn set_realm_provider_id(id: String) {
    REALM_PROVIDER_ID.set(id).ok();
}

/// Per-VU SCIM sync session state: the API Key bearer token minted in
/// `provision_api_key` and the SCIM user id created in `sync_create`.
#[derive(Default)]
pub struct ScimSession {
    pub bearer: Option<String>,
    pub user_id: Option<String>,
    pub external_id: Option<String>,
}

/// Mint a per-VU API Key bound to the seeded realm's `provider_id` (on_start,
/// admin-token setup step -- not itself part of the simulated sync traffic).
/// Mirrors `v4::api_key::create` but keeps the full bearer `token`, which
/// that module never needs since it never calls `/SCIM/v2`.
pub async fn provision_api_key(user: &mut GooseUser) -> TransactionResult {
    let Some(provider_id) = REALM_PROVIDER_ID.get() else {
        return Ok(());
    };
    let session = user.get_session_data_unchecked::<crate::Session>();
    let admin_token = session.token.clone();

    let expires_at = Utc::now() + Duration::hours(1);
    let body = json!({
        "api_key": {
            "domain_id": DEFAULT_DOMAIN_ID,
            "provider_id": provider_id,
            "expires_at": expires_at.to_rfc3339(),
            "description": "loadtest SCIM sync connector"
        }
    });

    let req = user
        .get_request_builder(&GooseMethod::Post, "/v4/api-keys")?
        .header("x-auth-token", &admin_token)
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("POST /v4/api-keys (SCIM sync setup)")
        .set_request_builder(req)
        .build();

    let mut goose = user.request(goose_request).await?;
    let response = match goose.response {
        Ok(r) => r,
        Err(e) => {
            return user.set_failure(
                &format!("scim_sync api_key provision failed: {e}"),
                &mut goose.request,
                None,
                None,
            );
        }
    };
    if !response.status().is_success() {
        return user.set_failure(
            &format!("scim_sync api_key provision returned {}", response.status()),
            &mut goose.request,
            None,
            None,
        );
    }

    let val: serde_json::Value = response.json().await.unwrap_or_default();
    let bearer = val["token"].as_str().map(str::to_owned);

    user.set_session_data(ScimSession {
        bearer,
        user_id: None,
        external_id: None,
    });
    Ok(())
}

fn bearer_header(user: &GooseUser) -> Option<String> {
    user.get_session_data::<ScimSession>()
        .and_then(|s| s.bearer.clone())
        .map(|b| format!("Bearer {b}"))
}

/// `POST /SCIM/v2/{domain_id}/Users` -- an IdP connector provisioning a new
/// user (ADR 0024 §3.C/§3.D). `externalId` is the IdP-side identifier a real
/// sync connector uses to converge repeat syncs onto the same shadow user.
pub async fn sync_create(user: &mut GooseUser) -> TransactionResult {
    let Some(auth) = bearer_header(user) else {
        return Ok(());
    };

    let external_id = format!("loadtest-ext-{}", Uuid::new_v4().as_simple());
    let user_name = format!("loadtest-scim-{}", Uuid::new_v4().as_simple());
    let body = json!({
        "schemas": [USER_SCHEMA],
        "externalId": external_id,
        "userName": user_name,
        "name": {"givenName": "Load", "familyName": "Test"},
        "emails": [{"value": format!("{user_name}@example.org"), "primary": true}],
        "active": true
    });

    let path = format!("/SCIM/v2/{DEFAULT_DOMAIN_ID}/Users");
    let req = user
        .get_request_builder(&GooseMethod::Post, &path)?
        .header("authorization", &auth)
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("POST /SCIM/v2/:domain_id/Users (sync provision)")
        .set_request_builder(req)
        .build();

    let mut goose = user.request(goose_request).await?;
    let response = match goose.response {
        Ok(r) => r,
        Err(e) => {
            return user.set_failure(
                &format!("scim sync_create failed: {e}"),
                &mut goose.request,
                None,
                None,
            );
        }
    };
    if !response.status().is_success() {
        return user.set_failure(
            &format!("scim sync_create returned {}", response.status()),
            &mut goose.request,
            None,
            None,
        );
    }
    let val: serde_json::Value = response.json().await.unwrap_or_default();
    let user_id = val["id"].as_str().map(str::to_owned);

    let session = user.get_session_data_unchecked_mut::<ScimSession>();
    session.user_id = user_id;
    session.external_id = Some(external_id);
    Ok(())
}

/// `GET /SCIM/v2/{domain_id}/Users?filter=userName eq "..."` -- the
/// reconciliation read a sync connector issues each cycle to check for
/// drift before deciding whether to `PATCH`/`PUT`.
pub async fn sync_list(user: &mut GooseUser) -> TransactionResult {
    let Some(auth) = bearer_header(user) else {
        return Ok(());
    };

    let path = format!("/SCIM/v2/{DEFAULT_DOMAIN_ID}/Users?count=20");
    let req = user
        .get_request_builder(&GooseMethod::Get, &path)?
        .header("authorization", &auth);

    let goose_request = GooseRequest::builder()
        .name("GET /SCIM/v2/:domain_id/Users (sync reconcile list)")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// `GET /SCIM/v2/{domain_id}/Users/{id}` -- per-record reconciliation read.
pub async fn sync_show(user: &mut GooseUser) -> TransactionResult {
    let Some(auth) = bearer_header(user) else {
        return Ok(());
    };
    let Some(user_id) = user
        .get_session_data::<ScimSession>()
        .and_then(|s| s.user_id.clone())
    else {
        return Ok(());
    };

    let path = format!("/SCIM/v2/{DEFAULT_DOMAIN_ID}/Users/{user_id}");
    let req = user
        .get_request_builder(&GooseMethod::Get, &path)?
        .header("authorization", &auth);

    let goose_request = GooseRequest::builder()
        .name("GET /SCIM/v2/:domain_id/Users/:id (sync reconcile show)")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// `PATCH /SCIM/v2/{domain_id}/Users/{id}` -- an IdP-side attribute change
/// (e.g. `displayName` edited upstream) landing as a partial update, the
/// dominant write shape in steady-state sync (RFC 7644 §3.5.2, ADR 0024
/// §5.C).
pub async fn sync_patch(user: &mut GooseUser) -> TransactionResult {
    let Some(auth) = bearer_header(user) else {
        return Ok(());
    };
    let Some(user_id) = user
        .get_session_data::<ScimSession>()
        .and_then(|s| s.user_id.clone())
    else {
        return Ok(());
    };

    let body = json!({
        "schemas": [PATCH_OP_SCHEMA],
        "Operations": [
            {"op": "replace", "path": "displayName", "value": "Load Test (synced)"}
        ]
    });

    let path = format!("/SCIM/v2/{DEFAULT_DOMAIN_ID}/Users/{user_id}");
    let req = user
        .get_request_builder(&GooseMethod::Patch, &path)?
        .header("authorization", &auth)
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("PATCH /SCIM/v2/:domain_id/Users/:id (sync attribute drift)")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// `DELETE /SCIM/v2/{domain_id}/Users/{id}` -- offboarding, the terminal
/// event of a sync cycle when the IdP-side record is removed (on_stop).
pub async fn sync_delete(user: &mut GooseUser) -> TransactionResult {
    let Some(auth) = bearer_header(user) else {
        return Ok(());
    };
    let Some(user_id) = user
        .get_session_data::<ScimSession>()
        .and_then(|s| s.user_id.clone())
    else {
        return Ok(());
    };

    let path = format!("/SCIM/v2/{DEFAULT_DOMAIN_ID}/Users/{user_id}");
    let req = user
        .get_request_builder(&GooseMethod::Delete, &path)?
        .header("authorization", &auth);

    let goose_request = GooseRequest::builder()
        .name("DELETE /SCIM/v2/:domain_id/Users/:id (sync offboard)")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;

    let session = user.get_session_data_unchecked_mut::<ScimSession>();
    session.user_id = None;
    Ok(())
}
