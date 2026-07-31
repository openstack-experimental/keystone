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
//! Raft-backed Unified Mapping Engine ruleset CRUD, ADR 0020.
//!
//! `mapping-driver-raft` is the largest raft driver in the workspace -- rules
//! can carry nested authorizations/groups/identity bindings, so this exercises
//! larger raft log entries than the simple api_key/oauth2_client payloads.

use goose::prelude::*;
use serde_json::json;
use uuid::Uuid;

use crate::Session;

/// List mapping rulesets (raft read path).
pub async fn list(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let req = user
        .get_request_builder(&GooseMethod::Get, "/v4/mappings/rulesets")?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("GET /v4/mappings/rulesets")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// Create a mapping ruleset owned by this virtual user (on_start for MappingCRUD).
pub async fn create(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let idp_id = format!("loadtest-idp-{}", Uuid::new_v4().as_simple());
    let body = json!({
        "mapping": {
            "domain_resolution_mode": { "type": "fixed" },
            "enabled": true,
            "source": { "type": "federation", "idp_id": idp_id },
            "rules": [{
                "name": "loadtest-rule",
                "description": "loadtest rule",
                "match": {
                    "all_of": [{
                        "type": "condition",
                        "equals": { "claim": "sub", "value": "loadtest" }
                    }]
                },
                "identity": { "user_name": "loadtest-user" },
                "groups": [],
                "authorizations": []
            }]
        }
    });

    let req = user
        .get_request_builder(&GooseMethod::Post, "/v4/mappings/rulesets")?
        .header("x-auth-token", &token)
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("POST /v4/mappings/rulesets (setup)")
        .set_request_builder(req)
        .build();

    let mut goose = user.request(goose_request).await?;
    let response = match goose.response {
        Ok(r) => r,
        Err(e) => {
            return user.set_failure(
                &format!("mapping ruleset create failed: {e}"),
                &mut goose.request,
                None,
                None,
            );
        }
    };

    if !response.status().is_success() {
        return user.set_failure(
            &format!("mapping ruleset create returned {}", response.status()),
            &mut goose.request,
            None,
            None,
        );
    }

    let val: serde_json::Value = response.json().await.unwrap_or_default();
    let mapping_id = val["mapping"]["mapping_id"].as_str().map(str::to_owned);

    let session = user.get_session_data_unchecked_mut::<Session>();
    session.mapping_id = mapping_id;

    Ok(())
}

/// Show the mapping ruleset owned by this virtual user.
pub async fn show(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();
    let mapping_id = match &session.mapping_id {
        Some(id) => id.clone(),
        None => return Ok(()),
    };

    let path = format!("/v4/mappings/rulesets/{mapping_id}");
    let req = user
        .get_request_builder(&GooseMethod::Get, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("GET /v4/mappings/rulesets/:mapping_id")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// Delete the mapping ruleset owned by this virtual user (on_stop for MappingCRUD).
pub async fn delete(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();
    let mapping_id = match &session.mapping_id {
        Some(id) => id.clone(),
        None => return Ok(()),
    };

    let path = format!("/v4/mappings/rulesets/{mapping_id}");
    let req = user
        .get_request_builder(&GooseMethod::Delete, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("DELETE /v4/mappings/rulesets/:mapping_id (teardown)")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;

    let session = user.get_session_data_unchecked_mut::<Session>();
    session.mapping_id = None;

    Ok(())
}
