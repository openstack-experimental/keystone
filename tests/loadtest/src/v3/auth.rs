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

use goose::prelude::*;
use serde_json::json;

use crate::Session;

/// Validate the session token against itself (cheap hot-path test).
pub async fn validate(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let req = user
        .get_request_builder(&GooseMethod::Get, "/v3/auth/tokens")?
        .header("x-auth-token", &token)
        .header("x-subject-token", &token);

    let goose_request = GooseRequest::builder().set_request_builder(req).build();

    user.request(goose_request).await?;
    Ok(())
}

/// Issue a new token via token re-auth, validate it, then revoke it.
///
/// This exercises the full token lifecycle: create → validate → delete.
/// Token re-auth is used so no stored password is required.
pub async fn token_lifecycle(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let existing_token = session.token.clone();

    // Issue a new token by re-authenticating with the existing token.
    let body = json!({
        "auth": {
            "identity": {
                "methods": ["token"],
                "token": { "id": existing_token }
            }
        }
    });

    let create_req = user
        .get_request_builder(&GooseMethod::Post, "/v3/auth/tokens")?
        .header("x-auth-token", &existing_token)
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("POST /v3/auth/tokens")
        .set_request_builder(create_req)
        .build();

    let mut goose = user.request(goose_request).await?;
    let response = match goose.response {
        Ok(r) => r,
        Err(e) => {
            return user.set_failure(
                &format!("token create failed: {e}"),
                &mut goose.request,
                None,
                None,
            );
        }
    };

    if !response.status().is_success() {
        return user.set_failure(
            &format!("token create returned {}", response.status()),
            &mut goose.request,
            None,
            None,
        );
    }

    let new_token = match response.headers().get("x-subject-token") {
        Some(v) => v.to_str().unwrap_or("").to_owned(),
        None => {
            return user.set_failure(
                "token create response missing X-Subject-Token",
                &mut goose.request,
                None,
                None,
            );
        }
    };

    // Validate the newly issued token.
    let validate_req = user
        .get_request_builder(&GooseMethod::Get, "/v3/auth/tokens")?
        .header("x-auth-token", &existing_token)
        .header("x-subject-token", &new_token);

    let goose_request = GooseRequest::builder()
        .name("GET /v3/auth/tokens (validate new)")
        .set_request_builder(validate_req)
        .build();

    user.request(goose_request).await?;

    // Revoke the newly issued token.
    let revoke_req = user
        .get_request_builder(&GooseMethod::Delete, "/v3/auth/tokens")?
        .header("x-auth-token", &existing_token)
        .header("x-subject-token", &new_token);

    let goose_request = GooseRequest::builder()
        .name("DELETE /v3/auth/tokens")
        .set_request_builder(revoke_req)
        .build();

    user.request(goose_request).await?;

    Ok(())
}
