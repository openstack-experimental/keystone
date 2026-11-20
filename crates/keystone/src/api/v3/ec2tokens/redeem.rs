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
//! Credential redemption shared by `/v3/ec2tokens` and `/v3/s3tokens`
//! (ADR 0019 §5): hardened credential lookup, enabled checks, delegation
//! (trust / application credential) reconstruction and scope bounding.

use serde_json::Value;

use openstack_keystone_core_types::auth::AuthenticationError;
use openstack_keystone_core_types::auth::ScopeInfo;
use openstack_keystone_core_types::credential::Credential as CoreCredential;

use crate::api::error::KeystoneApiError;
use crate::auth::*;
use crate::keystone::ServiceState;

/// Look the credential up by EC2 access key, run `verify(secret, auth_ttl_seconds)`
/// and rebuild the authentication context from the credential.
///
/// The returned context carries the `ec2credential` authentication method
/// marker. Callers that do not hand the token out still get a validated
/// context whose `Token` is built in memory only (fernet tokens are
/// stateless; nothing is stored).
pub(crate) async fn redeem_ec2_credential(
    state: &ServiceState,
    access: &str,
    verify: impl FnOnce(&str, i64) -> Result<(), AuthenticationError>,
) -> Result<ValidatedSecurityContext, KeystoneApiError> {
    let exec = ExecutionContext::internal(state);

    let credential: CoreCredential = state
        .provider
        .get_credential_provider()
        .get_credential_by_ec2_access(&exec, access)
        .await?
        .ok_or(AuthenticationError::Ec2AccessKeyNotFound)?;

    // Defense-in-depth (ADR 0019 §5): `get_credential_by_ec2_access` keys on
    // `SHA-256(access) == credential.id`, an invariant only established for
    // `type == "ec2"` credentials at creation. Reject any other type so a
    // credential mislabelled to dodge the ec2 create-time guards
    // (project binding, delegation stamping, restricted-app-cred gate —
    // OSSA-2026-005) can never be redeemed here even if its id were to
    // collide with an access hash.
    if credential.r#type != "ec2" {
        return Err(AuthenticationError::Ec2AccessKeyNotFound.into());
    }

    let blob: Value = serde_json::from_str(&credential.blob).map_err(|e| {
        KeystoneApiError::InternalError(format!(
            "credential {}: corrupted ec2 blob: {e}",
            credential.id
        ))
    })?;
    let secret = blob.get("secret").and_then(Value::as_str).ok_or_else(|| {
        KeystoneApiError::InternalError(format!(
            "credential {}: ec2 blob missing `secret`",
            credential.id
        ))
    })?;
    // `[credential] auth_ttl` is in minutes (Python compatible).
    let auth_ttl_seconds = state
        .config_manager
        .config
        .read()
        .await
        .credential
        .auth_ttl
        .saturating_mul(60);

    // Verified before any further per-credential state (OAuth1, project,
    // user/domain enabled) is inspected, so an unauthenticated caller who only
    // knows an access key cannot tell a disabled user or a malformed
    // credential from a bad signature (no pre-auth state oracle).
    // Signature (and replay window) verification is supplied by the caller
    // since the wire formats differ (`/v3/ec2tokens` vs `/v3/s3tokens`).
    verify(secret, auth_ttl_seconds)?;

    let trust_id = blob.get("trust_id").and_then(Value::as_str);
    let app_cred_id = blob.get("app_cred_id").and_then(Value::as_str);

    // OAuth1 access-token-bound EC2 credentials (`access_token_id`) are not
    // supported: OAuth1 is not implemented, so redeeming such a credential
    // would silently fall through to a plain `Ec2Credential` context and
    // drop the intended OAuth1 delegation restriction (OSSA-2026-005
    // family). Fail closed until the OAuth1 delegation is wired through.
    if blob
        .get("access_token_id")
        .and_then(Value::as_str)
        .is_some()
    {
        return Err(KeystoneApiError::InternalError(format!(
            "credential {}: OAuth1 access-token-bound EC2 credentials are not supported",
            credential.id
        )));
    }

    let project_id = credential.project_id.clone().ok_or_else(|| {
        KeystoneApiError::InternalError(format!(
            "credential {}: ec2 credential missing project_id",
            credential.id
        ))
    })?;

    // User/domain enabled checks (ADR 0019 §5 step 4). Project/project-domain
    // enabled is checked below by `get_authz_info`'s `ScopeInfo::validate()`.
    let user = state
        .provider
        .get_identity_provider()
        .get_user(&exec, &credential.user_id)
        .await?
        .ok_or(AuthenticationError::Ec2AccessKeyNotFound)?;
    if !user.enabled {
        return Err(AuthenticationError::UserDisabled(user.id.clone()).into());
    }
    // The reference form (no domain options) is all that is needed here, and
    // the request cache makes the repeated lookups of the same domain below
    // (the project domain is usually the user domain) free.
    let resource_provider = state.provider.get_resource_provider();
    let user_domain = resource_provider
        .get_domain_ref(&exec, &user.domain_id)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "domain".into(),
            identifier: user.domain_id.clone(),
        })?;
    if !user_domain.enabled {
        return Err(AuthenticationError::UserDomainDisabled.into());
    }

    let principal = PrincipalInfo {
        identity: IdentityInfo::User(
            UserIdentityInfoBuilder::default()
                .user_id(user.id.clone())
                .user(user.clone())
                .user_domain(user_domain.clone())
                .build()?,
        ),
    };

    // Delegation metadata pass-through (ADR 0019 §5, "Credential metadata in
    // the token"): reuse the existing Trust/ApplicationCredential contexts so
    // the bounded-object validation already wired into
    // `ValidatedSecurityContext::new_for_scope` (trustee/expiry checks)
    // applies unchanged.
    let context = if let Some(tid) = trust_id {
        let trust = state
            .provider
            .get_trust_provider()
            .get_trust(&exec, tid)
            .await?
            .ok_or_else(|| KeystoneApiError::not_found("trust", tid))?;
        AuthenticationContext::Trust { trust, token: None }
    } else if let Some(aid) = app_cred_id {
        let application_credential = state
            .provider
            .get_application_credential_provider()
            .get_application_credential(&exec, aid)
            .await?
            .ok_or_else(|| KeystoneApiError::not_found("application_credential", aid))?;
        AuthenticationContext::ApplicationCredential {
            application_credential,
            token: None,
        }
    } else {
        AuthenticationContext::Ec2Credential
    };

    let auth_result = AuthenticationResultBuilder::default()
        .context(context)
        .principal(principal)
        .build()?;

    let ctx = SecurityContext::try_from(auth_result)?;
    // The token scope only carries the short form of the project and of its
    // domain, so neither the project options nor the tags are loaded.
    let project = resource_provider
        .get_project_ref(&exec, &project_id)
        .await?
        .ok_or(KeystoneApiError::UnauthorizedNoContext)?;
    let project_domain = resource_provider
        .get_domain_ref(&exec, &project.domain_id)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "domain".into(),
            identifier: project.domain_id.clone(),
        })?;
    let authz_info = ScopeInfo::Project {
        project,
        project_domain,
    };
    authz_info.validate()?;

    let vsc = state
        .provider
        .get_token_provider()
        .issue_token_context(state, &ctx, &authz_info)
        .await?;
    Ok(vsc)
}
