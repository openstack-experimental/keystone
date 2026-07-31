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
//! Raft-backed API Key (SCIM ingress machine identity) CRUD, ADR 0021.
//!
//! Every write goes through `api-key-driver-raft` -- create/revoke are raft
//! log-append + quorum-commit operations, unlike the SQL-backed v3 CRUD.

use chrono::{Duration, Utc};
use goose::prelude::*;
use serde_json::json;
use uuid::Uuid;

use crate::Session;

const DEFAULT_DOMAIN_ID: &str = "default";

/// List API keys (raft read path). `domain_id` is a mandatory filter (ADR
/// 0021 §5.B) -- API keys are always domain-owned, no "all domains" mode.
pub async fn list(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let path = format!("/v4/api-keys?domain_id={DEFAULT_DOMAIN_ID}");
    let req = user
        .get_request_builder(&GooseMethod::Get, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("GET /v4/api-keys")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// Create an API key owned by this virtual user (on_start for ApiKeyCRUD).
pub async fn create(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let provider_id = format!("loadtest-provider-{}", Uuid::new_v4().as_simple());
    let expires_at = Utc::now() + Duration::hours(1);
    let body = json!({
        "api_key": {
            "domain_id": DEFAULT_DOMAIN_ID,
            "provider_id": provider_id,
            "expires_at": expires_at.to_rfc3339(),
            "description": "loadtest key"
        }
    });

    let req = user
        .get_request_builder(&GooseMethod::Post, "/v4/api-keys")?
        .header("x-auth-token", &token)
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("POST /v4/api-keys (setup)")
        .set_request_builder(req)
        .build();

    let mut goose = user.request(goose_request).await?;
    let response = match goose.response {
        Ok(r) => r,
        Err(e) => {
            return user.set_failure(
                &format!("api_key create failed: {e}"),
                &mut goose.request,
                None,
                None,
            );
        }
    };

    if !response.status().is_success() {
        return user.set_failure(
            &format!("api_key create returned {}", response.status()),
            &mut goose.request,
            None,
            None,
        );
    }

    let val: serde_json::Value = response.json().await.unwrap_or_default();
    let client_id = val["api_key"]["client_id"].as_str().map(str::to_owned);

    let session = user.get_session_data_unchecked_mut::<Session>();
    session.api_key_client_id = client_id;

    Ok(())
}

/// Show the API key owned by this virtual user.
pub async fn show(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();
    let client_id = match &session.api_key_client_id {
        Some(id) => id.clone(),
        None => return Ok(()),
    };

    let path = format!("/v4/api-keys/{client_id}?domain_id={DEFAULT_DOMAIN_ID}");
    let req = user
        .get_request_builder(&GooseMethod::Get, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("GET /v4/api-keys/:client_id")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// Revoke the API key owned by this virtual user (on_stop for ApiKeyCRUD).
pub async fn revoke(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();
    let client_id = match &session.api_key_client_id {
        Some(id) => id.clone(),
        None => return Ok(()),
    };

    let path = format!("/v4/api-keys/{client_id}/revoke?domain_id={DEFAULT_DOMAIN_ID}");
    let req = user
        .get_request_builder(&GooseMethod::Post, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("POST /v4/api-keys/:client_id/revoke (teardown)")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;

    let session = user.get_session_data_unchecked_mut::<Session>();
    session.api_key_client_id = None;

    Ok(())
}
