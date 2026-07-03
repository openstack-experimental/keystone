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
//! `/v3/credentials` API (ADR 0019).

use serde::Serialize;
use serde_json::{Value, json};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

/// Build a `{"credential": ...}` policy-input value with the decrypted
/// `blob` stripped out.
///
/// # Security Note
///
/// A credential's `blob` holds the *decrypted* secret (EC2 secret key, TOTP
/// seed, ...). No credential `.rego` rule references it, so it must never be
/// shipped to the policy engine: an external OPA can persist policy input via
/// decision logging, which would turn the authorization channel into a secret
/// exfiltration path. On any serialization failure this yields a `null`
/// credential, which every credential policy treats as deny (fail closed).
pub(super) fn credential_policy_input<T: Serialize>(credential: &T) -> Value {
    let credential = serde_json::to_value(credential)
        .map(|mut v| {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("blob");
            }
            v
        })
        .unwrap_or(Value::Null);
    json!({ "credential": credential })
}

mod create;
mod delete;
mod list;
mod show;
pub mod types;
mod update;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list, create::create))
        .routes(routes!(show::show, delete::delete))
        .routes(routes!(update::update))
}

#[cfg(test)]
mod tests {}
