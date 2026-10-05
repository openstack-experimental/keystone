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
//! # `id_token` claim construction (ADR 0026 §4, "Claim Safety")
//!
//! Shared by the `authorization_code` and `device_code` grants (and meant
//! for `/userinfo`): standard OIDC claims gated by the granted scope plus
//! the per-client `claims_template` output.
use std::collections::HashMap;

use serde_json::{Value, json};
use thiserror::Error;

use openstack_keystone_core_types::identity::UserResponse;
use openstack_keystone_core_types::oauth2_client::{IdTokenClaims, OAuth2ClientResource};

use crate::auth::ExecutionContext;
use crate::keystone::ServiceState;
use crate::oauth2_client::service::RESERVED_CLAIM_NAMES;

/// Errors raised while building the `id_token` claims. Never produces a
/// partial token: the caller must fail the issuance.
#[derive(Debug, Error)]
pub enum IdTokenClaimsError {
    /// The user could not be loaded.
    #[error("user lookup failed: {0}")]
    Identity(String),

    /// The user does not exist anymore.
    #[error("user {0} not found")]
    UserNotFound(String),

    /// Malformed template (unknown variable or unterminated `${`).
    #[error("invalid claims_template for claim `{claim}`: {reason}")]
    InvalidTemplate {
        /// Claim name.
        claim: String,
        /// Failure reason.
        reason: String,
    },

    /// The interpolated value contains control characters.
    #[error("claims_template output for claim `{0}` contains control characters")]
    ControlCharacters(String),

    /// The claim name is reserved.
    #[error("claims_template key `{0}` collides with a reserved claim name")]
    ReservedClaim(String),
}

/// Authorization scope identifiers available to `${scope.*}` variables.
#[derive(Clone, Debug, Default)]
pub struct TemplateScope {
    /// `${scope.project_id}`.
    pub project_id: Option<String>,
    /// `${scope.domain_id}`.
    pub domain_id: Option<String>,
    /// `${scope.system_id}`.
    pub system_id: Option<String>,
}

/// Inputs of the `id_token` that do not depend on the user record.
#[derive(Clone, Debug)]
pub struct IdTokenParams {
    /// Issuer URL.
    pub issuer: String,
    /// Authenticated user ID (`sub`).
    pub user_id: String,
    /// Relying party `client_id` (`aud`).
    pub client_id: String,
    /// Issued-at, Unix seconds.
    pub now: i64,
    /// Lifetime in seconds.
    pub lifetime: i64,
    /// Time of primary authentication.
    pub auth_time: i64,
    /// `/authorize` nonce.
    pub nonce: Option<String>,
    /// Authentication methods references.
    pub amr: Vec<String>,
    /// `at_hash` of the co-issued access token.
    pub at_hash: Option<String>,
}

fn is_forbidden_char(c: char) -> bool {
    matches!(c, '\u{0000}'..='\u{001F}' | '\u{007F}'..='\u{009F}')
}

const KNOWN_VARIABLES: &[&str] = &[
    "user.id",
    "user.domain_id",
    "scope.project_id",
    "scope.domain_id",
    "scope.system_id",
];

/// Check that every `${...}` in the template names a supported variable.
pub fn validate_template(template: &str) -> Result<(), String> {
    interpolate(template, |name| {
        if KNOWN_VARIABLES.contains(&name) {
            Ok(Some(String::new()))
        } else {
            Err(format!("unknown variable `${{{name}}}`"))
        }
    })
    .map(|_| ())
}

/// Single-pass interpolation. The resolver returns `Ok(None)` when the
/// variable is valid but has no value, which yields `Ok(None)` overall.
/// Substituted values are never re-scanned.
fn interpolate<F>(template: &str, mut resolve: F) -> Result<Option<String>, String>
where
    F: FnMut(&str) -> Result<Option<String>, String>,
{
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    let mut unresolved = false;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| "unterminated `${`".to_string())?;
        match resolve(&after[..end])? {
            Some(v) => out.push_str(&v),
            None => unresolved = true,
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok((!unresolved).then_some(out))
}

/// Interpolate every `claims_template` entry. Claims referencing a scope
/// variable that has no value in this grant are omitted.
pub fn interpolate_claims_template(
    template: &HashMap<String, String>,
    user: &UserResponse,
    scope: &TemplateScope,
) -> Result<HashMap<String, Value>, IdTokenClaimsError> {
    let mut out = HashMap::new();
    for (claim, tpl) in template {
        if RESERVED_CLAIM_NAMES.contains(&claim.as_str()) {
            return Err(IdTokenClaimsError::ReservedClaim(claim.clone()));
        }
        let value = interpolate(tpl, |name| match name {
            "user.id" => Ok(Some(user.id.clone())),
            "user.domain_id" => Ok(Some(user.domain_id.clone())),
            "scope.project_id" => Ok(scope.project_id.clone()),
            "scope.domain_id" => Ok(scope.domain_id.clone()),
            "scope.system_id" => Ok(scope.system_id.clone()),
            other => Err(format!("unknown variable `${{{other}}}`")),
        })
        .map_err(|reason| IdTokenClaimsError::InvalidTemplate {
            claim: claim.clone(),
            reason,
        })?;
        let Some(value) = value else { continue };
        if value.chars().any(is_forbidden_char) {
            return Err(IdTokenClaimsError::ControlCharacters(claim.clone()));
        }
        out.insert(claim.clone(), Value::String(value));
    }
    Ok(out)
}

/// OIDC Core §5.1 standard claims gated by the granted scope.
pub fn standard_claims(user: &UserResponse, scope: &[String]) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    if scope.iter().any(|s| s == "profile") {
        out.insert("name".to_string(), json!(user.name));
        out.insert("preferred_username".to_string(), json!(user.name));
        if let Some(updated_at) = user.extra.get("updated_at").filter(|v| v.is_i64()) {
            out.insert("updated_at".to_string(), updated_at.clone());
        }
    }
    if scope.iter().any(|s| s == "email")
        && let Some(email) = user.extra.get("email").and_then(Value::as_str)
    {
        out.insert("email".to_string(), json!(email));
        // Keystone does not verify addresses.
        let verified = user
            .extra
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        out.insert("email_verified".to_string(), json!(verified));
    }
    out
}

/// Combine standard claims and the client's `claims_template` output.
/// `claims_template` entries override same-named standard claims; reserved
/// names are rejected.
pub fn build_extra_claims(
    client: &OAuth2ClientResource,
    user: &UserResponse,
    granted_scope: &[String],
    template_scope: &TemplateScope,
) -> Result<HashMap<String, Value>, IdTokenClaimsError> {
    let mut claims = standard_claims(user, granted_scope);
    claims.extend(interpolate_claims_template(
        &client.claims_template,
        user,
        template_scope,
    )?);
    Ok(claims)
}

/// Build the complete [`IdTokenClaims`], loading the user only when the
/// granted scope or the client's template needs it.
pub async fn build_id_token_claims(
    state: &ServiceState,
    client: &OAuth2ClientResource,
    params: IdTokenParams,
    granted_scope: &[String],
    template_scope: &TemplateScope,
) -> Result<IdTokenClaims, IdTokenClaimsError> {
    let needs_user = !client.claims_template.is_empty()
        || granted_scope.iter().any(|s| s == "profile" || s == "email");
    let extra_claims = if needs_user {
        let exec = ExecutionContext::internal(state);
        let user = state
            .provider
            .get_identity_provider()
            .get_user(&exec, &params.user_id)
            .await
            .map_err(|e| IdTokenClaimsError::Identity(e.to_string()))?
            .ok_or_else(|| IdTokenClaimsError::UserNotFound(params.user_id.clone()))?;
        build_extra_claims(client, &user, granted_scope, template_scope)?
    } else {
        HashMap::new()
    };
    Ok(IdTokenClaims {
        iss: params.issuer,
        sub: params.user_id,
        aud: params.client_id,
        exp: params.now + params.lifetime,
        iat: params.now,
        nbf: params.now,
        auth_time: params.auth_time,
        nonce: params.nonce,
        amr: params.amr,
        at_hash: params.at_hash,
        token_use: "id".to_string(),
        extra_claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> UserResponse {
        UserResponse {
            default_project_id: None,
            domain_id: "dom-1".into(),
            enabled: true,
            extra: HashMap::from([
                ("email".to_string(), json!("u@example.com")),
                ("updated_at".to_string(), json!(1700000000)),
            ]),
            federated: None,
            id: "user-1".into(),
            name: "alice".into(),
            options: Default::default(),
            password_expires_at: None,
        }
    }

    fn scope(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    fn tpl(k: &str, v: &str) -> HashMap<String, String> {
        HashMap::from([(k.to_string(), v.to_string())])
    }

    #[test]
    fn test_scope_gating() {
        assert!(standard_claims(&user(), &scope(&["openid"])).is_empty());
        let p = standard_claims(&user(), &scope(&["openid", "profile"]));
        assert_eq!(p["name"], "alice");
        assert_eq!(p["preferred_username"], "alice");
        assert_eq!(p["updated_at"], 1700000000);
        assert!(!p.contains_key("email"));
        let e = standard_claims(&user(), &scope(&["openid", "email"]));
        assert_eq!(e["email"], "u@example.com");
        assert_eq!(e["email_verified"], false);
        assert!(!e.contains_key("name"));
    }

    #[test]
    fn test_no_email_no_claim() {
        let mut u = user();
        u.extra.clear();
        assert!(standard_claims(&u, &scope(&["email"])).is_empty());
    }

    #[test]
    fn test_interpolate_each_variable() {
        let sc = TemplateScope {
            project_id: Some("p1".into()),
            domain_id: Some("d1".into()),
            system_id: Some("all".into()),
        };
        let t = HashMap::from([
            ("a".to_string(), "${user.id}".to_string()),
            ("b".to_string(), "dom:${user.domain_id}".to_string()),
            ("c".to_string(), "${scope.project_id}".to_string()),
            ("d".to_string(), "${scope.domain_id}".to_string()),
            ("e".to_string(), "${scope.system_id}".to_string()),
            ("f".to_string(), "static $ text".to_string()),
        ]);
        let out = interpolate_claims_template(&t, &user(), &sc).unwrap();
        assert_eq!(out["a"], "user-1");
        assert_eq!(out["b"], "dom:dom-1");
        assert_eq!(out["c"], "p1");
        assert_eq!(out["d"], "d1");
        assert_eq!(out["e"], "all");
        assert_eq!(out["f"], "static $ text");
    }

    #[test]
    fn test_unresolved_scope_omits_claim() {
        let out = interpolate_claims_template(
            &tpl("p", "${scope.project_id}"),
            &user(),
            &TemplateScope::default(),
        )
        .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn test_unknown_or_unterminated_rejected() {
        for bad in ["${user.name}", "${user.id", "${roles.x}"] {
            assert!(
                matches!(
                    interpolate_claims_template(&tpl("x", bad), &user(), &TemplateScope::default()),
                    Err(IdTokenClaimsError::InvalidTemplate { .. })
                ),
                "{bad}"
            );
            assert!(validate_template(bad).is_err());
        }
        assert!(validate_template("${user.id}-${scope.system_id}").is_ok());
    }

    #[test]
    fn test_single_pass_no_recursion() {
        let mut u = user();
        u.id = "${user.domain_id}".into();
        let out =
            interpolate_claims_template(&tpl("x", "${user.id}"), &u, &TemplateScope::default())
                .unwrap();
        assert_eq!(out["x"], "${user.domain_id}");
    }

    #[test]
    fn test_control_characters_rejected() {
        for c in ["\u{0000}", "\u{001F}", "\u{007F}", "\u{009F}", "\n"] {
            let t = tpl("x", &format!("a{c}b"));
            assert!(matches!(
                interpolate_claims_template(&t, &user(), &TemplateScope::default()),
                Err(IdTokenClaimsError::ControlCharacters(_))
            ));
        }
        // Via a substituted value.
        let mut u = user();
        u.domain_id = "d\u{0007}".into();
        assert!(
            interpolate_claims_template(
                &tpl("x", "${user.domain_id}"),
                &u,
                &TemplateScope::default()
            )
            .is_err()
        );
    }

    #[test]
    fn test_reserved_key_rejected() {
        let t = tpl("sub", "evil");
        assert!(matches!(
            interpolate_claims_template(&t, &user(), &TemplateScope::default()),
            Err(IdTokenClaimsError::ReservedClaim(_))
        ));
    }
}
