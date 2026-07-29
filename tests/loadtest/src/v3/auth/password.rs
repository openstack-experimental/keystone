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

//! Password authentication scenarios exercised against the pre-provisioned
//! seeded users (see `crate::seed`), each of which has a role assignment on
//! a shared "auth project" and a known shared password.

use goose::prelude::*;
use serde_json::json;

use crate::v3::user::{auth_project_id, random_seeded_cred};

/// Password auth with no scope requested.
pub async fn unscoped(user: &mut GooseUser) -> TransactionResult {
    let cred = match random_seeded_cred() {
        Some(c) => c,
        None => return Ok(()),
    };

    let body = json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "id": cred.id,
                        "password": cred.password
                    }
                }
            }
        }
    });

    let req = user
        .get_request_builder(&GooseMethod::Post, "/v3/auth/tokens")?
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("POST /v3/auth/tokens (password, unscoped)")
        .set_request_builder(req)
        .build();

    let mut goose = user.request(goose_request).await?;
    if let Ok(response) = &goose.response
        && !response.status().is_success()
    {
        let status = response.status();
        return user.set_failure(
            &format!("password auth (unscoped) returned {status}"),
            &mut goose.request,
            None,
            None,
        );
    }

    Ok(())
}

/// Password auth scoped to the shared auth project every seeded user has a
/// role assignment on.
pub async fn scoped(user: &mut GooseUser) -> TransactionResult {
    let cred = match random_seeded_cred() {
        Some(c) => c,
        None => return Ok(()),
    };
    let project_id = match auth_project_id() {
        Some(id) => id,
        None => return Ok(()),
    };

    let body = json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "id": cred.id,
                        "password": cred.password
                    }
                }
            },
            "scope": {
                "project": { "id": project_id }
            }
        }
    });

    let req = user
        .get_request_builder(&GooseMethod::Post, "/v3/auth/tokens")?
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("POST /v3/auth/tokens (password, project-scoped)")
        .set_request_builder(req)
        .build();

    let mut goose = user.request(goose_request).await?;
    if let Ok(response) = &goose.response
        && !response.status().is_success()
    {
        let status = response.status();
        return user.set_failure(
            &format!("password auth (project-scoped) returned {status}"),
            &mut goose.request,
            None,
            None,
        );
    }

    Ok(())
}

/// Password auth with a deliberately wrong password; must be rejected with
/// 401. Any other outcome (including success) is a Goose failure.
pub async fn invalid(user: &mut GooseUser) -> TransactionResult {
    let cred = match random_seeded_cred() {
        Some(c) => c,
        None => return Ok(()),
    };

    let body = json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "id": cred.id,
                        "password": format!("wrong-{}", cred.password)
                    }
                }
            }
        }
    });

    let req = user
        .get_request_builder(&GooseMethod::Post, "/v3/auth/tokens")?
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("POST /v3/auth/tokens (password, invalid)")
        .set_request_builder(req)
        .build();

    let mut goose = user.request(goose_request).await?;
    if let Ok(response) = &goose.response {
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            let status = response.status();
            return user.set_failure(
                &format!("invalid password auth returned {status}, expected 401"),
                &mut goose.request,
                None,
                None,
            );
        }
        // A wrong password is expected to be rejected with 401; mark this
        // non-2xx response as a success so it doesn't pollute Goose's error
        // stats with an expected negative-test outcome.
        return user.set_success(&mut goose.request);
    }

    Ok(())
}
