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

//! System-scoped auth using the initial bootstrap admin credentials, i.e.
//! the same identity `keystone-manage bootstrap` (see
//! `crates/cli-manage/src/bootstrap.rs`) provisions with a system `admin`
//! role. Defaults fall back to `OS_USERNAME`/`OS_PASSWORD`/
//! `OS_USER_DOMAIN_NAME` (the same vars `openstack_login`/`get_admin_token`
//! in `main.rs` use to reach the admin cloud), so this scenario's notion of
//! "the admin" can't silently drift from the rest of the suite's; only fall
//! further back to the `tools/start-api.sh`/`tools/start_keystone.sh`
//! convention (`admin`/`password`/`default`) when neither is set. Override
//! with `LOADTEST_ADMIN_USERNAME`/`_PASSWORD`/`_DOMAIN` if the target
//! deployment's admin identity differs from both.

use goose::prelude::*;
use serde_json::json;
use std::env;

fn admin_username() -> String {
    env::var("LOADTEST_ADMIN_USERNAME")
        .or_else(|_| env::var("OS_USERNAME"))
        .unwrap_or_else(|_| "admin".to_string())
}

fn admin_password() -> String {
    env::var("LOADTEST_ADMIN_PASSWORD")
        .or_else(|_| env::var("OS_PASSWORD"))
        .unwrap_or_else(|_| "password".to_string())
}

/// The admin's user domain, keeping track of whether the value is a domain
/// name or a domain id so it lands in the right JSON field — the two are
/// not interchangeable, and conflating them only happens to work when a
/// domain's id and name coincide (e.g. `default` in this dev convention).
enum AdminDomain {
    Name(String),
    Id(String),
}

impl AdminDomain {
    fn as_json(&self) -> serde_json::Value {
        match self {
            AdminDomain::Name(name) => json!({ "name": name }),
            AdminDomain::Id(id) => json!({ "id": id }),
        }
    }
}

fn admin_domain() -> AdminDomain {
    if let Ok(name) = env::var("LOADTEST_ADMIN_DOMAIN") {
        return AdminDomain::Name(name);
    }
    if let Ok(name) = env::var("OS_USER_DOMAIN_NAME") {
        return AdminDomain::Name(name);
    }
    if let Ok(id) = env::var("OS_USER_DOMAIN_ID") {
        return AdminDomain::Id(id);
    }
    // The id is the stable, always-lowercase identifier; the display name
    // (bootstrapped as "Default", capitalized) is a convention that can
    // vary by deployment, so falling back to it by name risks an exact-match
    // domain lookup failing even though the id would have resolved fine.
    AdminDomain::Id("default".to_string())
}

/// Authenticate as the bootstrap admin with system scope
/// (`{"system": {"all": true}}`), exercising the same path an operator uses
/// to get cloud-wide privileges.
pub async fn system_scope_auth(user: &mut GooseUser) -> TransactionResult {
    let body = json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": admin_username(),
                        "domain": admin_domain().as_json(),
                        "password": admin_password()
                    }
                }
            },
            "scope": {
                "system": { "all": true }
            }
        }
    });

    let req = user
        .get_request_builder(&GooseMethod::Post, "/v3/auth/tokens")?
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("POST /v3/auth/tokens (system-scoped, bootstrap admin)")
        .set_request_builder(req)
        .build();

    let mut goose = user.request(goose_request).await?;
    let response = match goose.response {
        Ok(r) => r,
        Err(e) => {
            return user.set_failure(
                &format!("system scope auth failed: {e}"),
                &mut goose.request,
                None,
                None,
            );
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        return user.set_failure(
            &format!("system scope auth returned {status}"),
            &mut goose.request,
            None,
            None,
        );
    }

    Ok(())
}
