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
//! `/v3/users/{user_id}/credentials/OS-EC2` legacy EC2 credentials API
//! (ADR 0019 §2/§3).

use serde_json::Value;
use utoipa_axum::{router::OpenApiRouter, routes};

use openstack_keystone_core_types::credential::Credential as CoreCredential;

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

mod create;
mod delete;
mod list;
mod show;
pub mod types;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list, create::create))
        .routes(routes!(show::show, delete::delete))
}

/// Flatten a stored `ec2` [`CoreCredential`]'s JSON `blob` into the
/// legacy OS-EC2 wire shape (ADR 0019 §3, "API Transformation Layer").
///
/// The `credential` table is shared with Python Keystone, so a
/// malformed/missing `access` or `secret` field indicates data corruption
/// rather than a client error — surfaced as `500` rather than `400`.
pub(super) fn to_ec2_credential(
    cred: CoreCredential,
) -> Result<types::Ec2Credential, KeystoneApiError> {
    let blob: Value = serde_json::from_str(&cred.blob).map_err(|e| {
        KeystoneApiError::InternalError(format!("credential {}: corrupted ec2 blob: {e}", cred.id))
    })?;
    let access = blob
        .get("access")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            KeystoneApiError::InternalError(format!(
                "credential {}: ec2 blob missing `access`",
                cred.id
            ))
        })?
        .to_string();
    let secret = blob
        .get("secret")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            KeystoneApiError::InternalError(format!(
                "credential {}: ec2 blob missing `secret`",
                cred.id
            ))
        })?
        .to_string();
    let trust_id = blob
        .get("trust_id")
        .and_then(Value::as_str)
        .map(String::from);

    Ok(types::Ec2Credential {
        access,
        secret,
        user_id: cred.user_id,
        project_id: cred.project_id.unwrap_or_default(),
        trust_id,
    })
}

#[cfg(test)]
mod tests {}
