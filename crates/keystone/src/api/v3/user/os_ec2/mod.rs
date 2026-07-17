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

/// Build an OS-EC2 credential policy-input value with the decrypted `blob`
/// stripped out.
///
/// # Security Note
///
/// `blob` holds the *decrypted* EC2 access/secret pair. No `os_ec2` `.rego`
/// rule references it, so it must never reach the policy engine -- see the
/// analogous `credential_policy_input` in the sibling `/v3/credentials`
/// module (`crate::api::v3::credential`) and `doc/src/security.md` I7.
pub(super) fn ec2_credential_policy_input(cred: &CoreCredential) -> Value {
    serde_json::to_value(cred)
        .map(|mut v| {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("blob");
            }
            v
        })
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::credential::CredentialBuilder;

    use super::ec2_credential_policy_input;
    use crate::api::tests::policy_contract;

    /// Gate I (security review V9, issue #987): direct, structural test on
    /// the OS-EC2 stripping helper itself -- see the analogous test for
    /// `credential_policy_input` in the sibling `/v3/credentials` module.
    #[test]
    fn test_ec2_credential_policy_input_never_leaks_blob() {
        let cred = CredentialBuilder::default()
            .id("cred_id")
            .blob(r#"{"access":"AKIA123","secret":"s3cr3t"}"#)
            .r#type("ec2")
            .user_id("uid")
            .project_id("pid")
            .build()
            .unwrap();

        let input = ec2_credential_policy_input(&cred);
        policy_contract::assert_no_secrets(&input);
        assert!(
            !input.to_string().contains("s3cr3t"),
            "serialized policy input must not contain the decrypted secret bytes"
        );
    }
}
