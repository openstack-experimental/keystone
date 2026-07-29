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

//! Token rescoping: re-authenticate with method "token" and a new `scope`.
//!
//! These scenarios reuse the `OS_CLOUD`-authenticated session token
//! (`Session.token`), which in the standard devstack/CI setup belongs to the
//! bootstrap admin user and therefore holds the system `admin` role — that
//! is what makes `rescope_to_system` expected to succeed. Running this
//! scenario against a cloud whose `OS_CLOUD` identity lacks a system role
//! assignment will surface as load-test failures.

use goose::prelude::*;
use serde_json::json;
use uuid::Uuid;

use crate::Session;

/// Rescope the current session token to system scope (`{"all": true}`).
pub async fn rescope_to_system(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let body = json!({
        "auth": {
            "identity": {
                "methods": ["token"],
                "token": { "id": token }
            },
            "scope": {
                "system": { "all": true }
            }
        }
    });

    let req = user
        .get_request_builder(&GooseMethod::Post, "/v3/auth/tokens")?
        .header("x-auth-token", &token)
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("POST /v3/auth/tokens (rescope to system)")
        .set_request_builder(req)
        .build();

    let mut goose = user.request(goose_request).await?;
    if let Ok(response) = &goose.response
        && !response.status().is_success()
    {
        let status = response.status();
        return user.set_failure(
            &format!("rescope to system scope returned {status}"),
            &mut goose.request,
            None,
            None,
        );
    }

    Ok(())
}

/// Attempt to rescope the current session token to a project that does not
/// exist; must be rejected. A successful response is a Goose failure.
pub async fn rescope_invalid_project(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();
    let bogus_project_id = Uuid::new_v4().as_simple().to_string();

    let body = json!({
        "auth": {
            "identity": {
                "methods": ["token"],
                "token": { "id": token }
            },
            "scope": {
                "project": { "id": bogus_project_id }
            }
        }
    });

    let req = user
        .get_request_builder(&GooseMethod::Post, "/v3/auth/tokens")?
        .header("x-auth-token", &token)
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("POST /v3/auth/tokens (rescope, invalid project)")
        .set_request_builder(req)
        .build();

    let mut goose = user.request(goose_request).await?;
    if let Ok(response) = &goose.response {
        if response.status().is_success() {
            return user.set_failure(
                "rescope to a nonexistent project unexpectedly succeeded",
                &mut goose.request,
                None,
                None,
            );
        }
        // Rescoping to a nonexistent project is expected to be rejected;
        // mark this non-2xx response as a success so it doesn't pollute
        // Goose's error stats with an expected negative-test outcome.
        return user.set_success(&mut goose.request);
    }

    Ok(())
}
