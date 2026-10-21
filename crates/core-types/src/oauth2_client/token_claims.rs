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
// Crypto inventory: TOK-11; see doc/src/contributor/crypto-inventory.md
//! # OAuth2 outbound access token claims (ADR 0026 §4)
//!
//! [`OpenStackAccessTokenClaims`] is the authorization claim set consumed by
//! downstream OpenStack services: issued unconditionally on the
//! `client_credentials` grant (Phase 3), and on `authorization_code`/
//! `refresh_token` grants (Phase 4) only when `openstack:api` was requested
//! and granted. [`IdTokenClaims`] (identity for the relying party) and
//! [`OidcAccessTokenClaims`] (the minimal RP-facing access token issued when
//! `openstack:api` was not granted) are Phase 4's `authorization_code`
//! deliverable.
use std::collections::HashMap;

use crate::role::RoleRef;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Identity claims delivered to the relying party (OIDC Core §2), issued as
/// the `id_token` on the `authorization_code` grant (ADR 0026 §4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer URL bound to the domain: `/v4/oauth2/{domain_id}`.
    pub iss: String,
    /// Keystone `user_id` (or virtual identity via HMAC-SHA256).
    pub sub: String,
    /// `OAuth2Client.client_id` of the consuming relying party.
    pub aud: String,
    /// Expiration, Unix seconds. Default 15 minutes
    /// (`[oauth2] id_token_lifetime_minutes`).
    pub exp: i64,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Not-before, always equal to `iat` (defense-in-depth per the Token
    /// Replay Model, ADR 0026 §4); verified by relying parties per OIDC
    /// Core §2.
    pub nbf: i64,
    /// Epoch timestamp of primary authentication (for `max_age`, OIDC Core
    /// §3.1.2.1).
    pub auth_time: i64,
    /// Echoed verbatim from the `/authorize` request (replay prevention).
    pub nonce: Option<String>,
    /// Authentication methods references (RFC 8176): `"pwd"`, `"otp"`,
    /// `"mfa"`, etc.
    pub amr: Vec<String>,
    /// Per OIDC Core §3.2.2.10: `SHA-256(access_token)[:96 bits, base64url]`.
    /// Binds the `id_token` to its co-issued `access_token`, preventing
    /// access-token substitution attacks at the RP. Omitted when no
    /// `access_token` is issued alongside it.
    pub at_hash: Option<String>,
    /// Identifier of the SSO session as seen by this relying party (OIDC
    /// Front/Back-Channel Logout `sid`); equals the `sid` of the logout
    /// token sent when that session ends. Omitted for grants without an
    /// SSO session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// Fixed `"id"` (OIDC Core §3.1.3.4). Downstream services reject this
    /// token as authorization.
    pub token_use: String,
    /// Per-`OAuth2Client` `claims_template` output (ADR 0026 §4, "Claim
    /// Safety"): interpolated `email`, `groups`, `roles`, etc.
    #[serde(flatten)]
    pub extra_claims: HashMap<String, serde_json::Value>,
}

/// `cnf` (confirmation) claim of a sender-constrained access token (RFC 7800,
/// RFC 9449 §6, ADR 0043 §3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Confirmation {
    /// RFC 7638 SHA-256 thumbprint of the DPoP proof key.
    pub jkt: String,
}

impl Confirmation {
    /// Whether the confirmation binds to the given proof key thumbprint
    /// (constant time). An empty `jkt` never matches.
    pub fn matches(&self, jkt: &str) -> bool {
        !self.jkt.is_empty() && bool::from(self.jkt.as_bytes().ct_eq(jkt.as_bytes()))
    }
}

/// Minimal `access_token` issued on `authorization_code`/`refresh_token`
/// grants that did NOT request (or were not granted) the `openstack:api`
/// scope (ADR 0026 §4, "Scope Validation"). Carries no OpenStack
/// authorization data at all -- no `openstack_context`, no roles, no
/// `openstack-apis` audience. Exists purely as the standard
/// RFC 6749 access token for calling Keystone's own `/userinfo` endpoint
/// (OIDC Core §5.3). This is what closes ADR 0026 §1 Threat Model item 1: a
/// compromised RP holding only this token has no `aud` value any downstream
/// OpenStack middleware will ever accept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcAccessTokenClaims {
    /// Issuer URL bound to the domain.
    pub iss: String,
    /// Keystone `user_id`.
    pub sub: String,
    /// The requesting `OAuth2Client.client_id` itself, NEVER
    /// `"openstack-apis"` (or a narrowing of it).
    pub aud: String,
    /// Expiration, Unix seconds. Mirrors `id_token` lifetime (default 15
    /// minutes).
    pub exp: i64,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Not-before, always equal to `iat`.
    pub nbf: i64,
    /// Unique token UUID.
    pub jti: String,
    /// Granted scope string, echoed per RFC 6749 §5.1.
    pub scope: String,
    /// Fixed `"access"` (mirrors [`IdTokenClaims::token_use`]); downstream
    /// middleware checks this alongside `openstack_context` presence.
    pub token_use: String,
    /// Refresh family: the `family_id` of the refresh-token family minted
    /// alongside (or rotated into) this token, when the client holds the
    /// `refresh_token` grant. Lets the RFC 7009 revocation endpoint end the
    /// whole family when an access token is revoked. Private claim, named
    /// `fid` so it is not mistaken for the OIDC `sid` of the SSO session
    /// (older tokens carry it as `sid`, which verification still accepts).
    #[serde(default, rename = "fid", skip_serializing_if = "Option::is_none")]
    pub family_id: Option<String>,
    /// DPoP binding of the token (ADR 0043 §3). Absent for bearer tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
}

/// Audience of an OpenStack access token: the whole control plane of the
/// deployment (ADR 0026 §5). Domain isolation is carried by `iss` and the
/// per-issuer JWKS, not by `aud`.
pub const OPENSTACK_APIS_AUDIENCE: &str = "openstack-apis";

/// Audience of an OpenStack access token narrowed to one service type
/// (`openstack-apis:<service type>`, ADR 0036 §7.1).
pub fn openstack_service_audience(service_type: &str) -> String {
    format!("{OPENSTACK_APIS_AUDIENCE}:{service_type}")
}

/// Whether `aud` is one of the audience values minted for OpenStack access
/// tokens (the control-plane value or a service-type narrowing of it), as
/// opposed to an OIDC access token whose audience is a `client_id`.
pub fn is_openstack_audience(aud: &str) -> bool {
    aud == OPENSTACK_APIS_AUDIENCE
        || aud
            .strip_prefix(OPENSTACK_APIS_AUDIENCE)
            .and_then(|rest| rest.strip_prefix(':'))
            .is_some_and(|service_type| !service_type.is_empty())
}

/// The `aud` claim (RFC 7519 §4.1.3): a single string or an array of strings.
///
/// Serializes a single value as a plain string and several values as an array,
/// so the default un-narrowed token stays `"aud": "openstack-apis"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// A single audience value.
    One(String),
    /// Several audience values.
    Many(Vec<String>),
}

impl Audience {
    /// The control-plane audience, [`OPENSTACK_APIS_AUDIENCE`].
    pub fn control_plane() -> Self {
        Self::One(OPENSTACK_APIS_AUDIENCE.to_string())
    }

    /// Audience narrowed to the given service types. An empty list yields the
    /// un-narrowed [`Audience::control_plane`]. Duplicates are dropped.
    pub fn narrowed<S: AsRef<str>>(service_types: &[S]) -> Self {
        let mut values: Vec<String> = Vec::new();
        for service_type in service_types {
            let value = openstack_service_audience(service_type.as_ref());
            if !values.contains(&value) {
                values.push(value);
            }
        }
        match values.len() {
            0 => Self::control_plane(),
            1 => Self::One(values.remove(0)),
            _ => Self::Many(values),
        }
    }

    /// The audience values as a slice.
    pub fn values(&self) -> &[String] {
        match self {
            Self::One(value) => std::slice::from_ref(value),
            Self::Many(values) => values,
        }
    }

    /// Whether this is an OpenStack access token audience: non-empty and every
    /// value is [`OPENSTACK_APIS_AUDIENCE`] or a narrowing of it. A mix with a
    /// foreign value (e.g. an OIDC `client_id`) is not an OpenStack audience.
    pub fn is_openstack(&self) -> bool {
        let values = self.values();
        !values.is_empty() && values.iter().all(|v| is_openstack_audience(v))
    }

    /// Whether `value` is one of the audience values.
    pub fn contains(&self, value: &str) -> bool {
        self.values().iter().any(|v| v == value)
    }
}

/// Authorization claims consumed by downstream OpenStack services (ADR 0026
/// §4). Issued as the `access_token` on `client_credentials` grants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenStackAccessTokenClaims {
    /// Issuer URL bound to the domain: `/v4/oauth2/{domain_id}`.
    pub iss: String,
    /// Keystone user_id (the ephemeral shadow `user_id` for
    /// `client_credentials`).
    pub sub: String,
    /// Control-plane audience `"openstack-apis"`, or its narrowing to
    /// `"openstack-apis:<service type>"` values (ADR 0026 §5, ADR 0036 §7.1).
    /// Domain isolation comes from `iss` plus the issuer's own JWKS.
    pub aud: Audience,
    /// The registered `OAuth2Client.client_id` that initiated the grant.
    pub client_id: String,
    /// Expiration, Unix seconds.
    pub exp: i64,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Not-before, always equal to `iat` (defense-in-depth per the Token
    /// Replay Model, ADR 0026 §4).
    pub nbf: i64,
    /// Unique token UUID for revocation mapping / audit trail.
    pub jti: String,
    /// Policy rule state anchor: the matched `MappingRuleSet.ruleset_version`.
    pub keystone_ruleset_version: u128,
    /// Authentication methods references (mirrors `id_token` for
    /// downstream). Always `["client_credentials"]` for this grant.
    pub amr: Vec<String>,
    /// Fixed `"access"` (OIDC Core §3.1.3.4 analogue); downstream middleware
    /// checks this alongside `openstack_context` presence.
    pub token_use: String,

    /// Delegated auth context. `client_credentials` only ever produces
    /// `Plain` in v1 — the three delegated variants are forward-declared so
    /// the type already matches what a future Token Exchange grant (ADR
    /// 0026 §12) will populate.
    pub delegation_context: DelegationContext,

    /// RFC 8693 `act`: the service acting for `sub`, on tokens a service
    /// obtained by redeeming a delegation (ADR 0036 §5.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<ActClaim>,

    /// DPoP binding of the token (ADR 0043 §3). Absent for bearer tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,

    #[serde(flatten)]
    pub openstack_context: OpenStackContext,
}

/// Delegated auth context: structurally enforces that a plain auth method
/// cannot carry a `delegated_project_id` (security.md I2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "auth_method", rename_all = "snake_case")]
pub enum DelegationContext {
    /// No delegation: the authenticated principal is the token subject
    /// directly. The only variant `client_credentials` produces in v1.
    Plain,
    /// Delegated via a trust.
    Trust {
        #[serde(rename = "delegated_project_id")]
        project_id: String,
    },
    /// Delegated via an application credential.
    AppCred {
        #[serde(rename = "delegated_project_id")]
        project_id: String,
    },
    /// Delegated via an EC2 credential.
    Ec2 {
        #[serde(rename = "delegated_project_id")]
        project_id: String,
    },
    /// A service acting for a user under a service grant (ADR 0036 §5.2).
    ServiceGrant {
        #[serde(rename = "delegated_project_id")]
        project_id: String,
        /// The redeemed grant.
        grant_id: String,
    },
    /// A service acting on a user's own token through an on-behalf-of
    /// exchange (ADR 0036 §6.2). Unlike the variants above it may carry no
    /// project: a plain subject has no delegation boundary.
    OnBehalfOf {
        /// The acting service's client id.
        actor_client_id: String,
        /// When the user authenticated, preserved on every re-exchange.
        auth_time: i64,
        /// Identifier of the user token that started the chain (§6.3).
        root_jti: String,
        /// The project of the subject's own delegation, if it had one.
        #[serde(
            default,
            rename = "delegated_project_id",
            skip_serializing_if = "Option::is_none"
        )]
        project_id: Option<String>,
        /// The roles of the subject's own delegation, if it had one. Every
        /// hop is bounded by them (security.md I4).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        delegated_role_ids: Option<Vec<String>>,
    },
}

/// Namespace of [`ActClaim::sub`] (ADR 0036 §5.2). Consumers branch on it
/// rather than on the shape of `sub`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActSubType {
    /// A SPIFFE ID: the service client's SVID.
    Spiffe,
    /// A Keystone user id (human grantee, ADR 0036 §9).
    UserId,
}

/// RFC 8693 §4.1 `act` claim: who acts for the token subject (ADR 0036
/// §5.2). Always present on a delegated service token; there is no way to
/// mint one that hides the acting service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActClaim {
    /// The acting service's client id.
    pub client_id: String,
    /// Namespace of `sub`.
    pub sub_type: ActSubType,
    /// The actor's identity in that namespace.
    pub sub: String,
}

/// OpenStack identity/authorization context embedded in an
/// [`OpenStackAccessTokenClaims`] via `#[serde(flatten)]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenStackContext {
    /// Core user UUID or virtual (shadow) identity string.
    pub user_id: String,
    /// Normalized, case-folded alphanumeric principal name.
    pub user_name: String,
    /// Home domain UUID of the identity itself, distinct from the scope
    /// below.
    pub user_domain_id: Option<String>,
    #[serde(flatten)]
    pub scope: OpenStackScope,
    /// Effective role names evaluated at token issuance.
    pub roles: Vec<String>,
}

/// The token's authorization scope. Mirrors
/// [`crate::mapping::authorization::Authorization`]'s shape (`Project`/
/// `Domain`/`System` variants, same `system_id` field name) but is a
/// distinct, outbound wire type: it additionally carries `Unscoped`, and is
/// tagged `scope_type` (the ADR 0026 §4 outbound claim name) rather than the
/// internal mapping type's `type` tag.
///
/// Each variant's `roles: Vec<RoleRef>` is wire-renamed to `scope_roles`
/// (`#[serde(rename = "scope_roles")]`) to avoid colliding with
/// [`OpenStackContext::roles`] (`Vec<String>`, the effective role *names*
/// the ADR §6 middleware reads via `ctx['roles']`): both fields flatten
/// into the same JSON object via nested `#[serde(flatten)]`, so an
/// unrenamed `roles` key here would silently duplicate that key on the
/// wire -- valid to write (`serde_json` simply overwrites the earlier
/// entry) but not valid to read back, since flattened deserialization
/// resolves each field by name against the *first* matching key rather
/// than the last. A signed token minted before this fix could never be
/// decoded back into this type at all.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "scope_type", rename_all = "snake_case")]
pub enum OpenStackScope {
    /// Project-scoped authorization.
    Project {
        /// Project UUID.
        project_id: String,
        /// Domain UUID the project belongs to.
        project_domain_id: String,
        /// Roles granted on this scope.
        #[serde(rename = "scope_roles")]
        roles: Vec<RoleRef>,
    },
    /// Domain-scoped authorization.
    Domain {
        /// Domain UUID.
        domain_id: String,
        /// Roles granted on this scope.
        #[serde(rename = "scope_roles")]
        roles: Vec<RoleRef>,
    },
    /// System-scoped authorization.
    System {
        /// System scope identifier (e.g. `"all"`).
        system_id: String,
        /// Roles granted on this scope.
        #[serde(rename = "scope_roles")]
        roles: Vec<RoleRef>,
    },
    /// No authorization scope.
    Unscoped,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confirmation_matches_constant_time_semantics() {
        let cnf = Confirmation { jkt: "abc".into() };
        assert!(cnf.matches("abc"));
        assert!(!cnf.matches("and"));
        assert!(!cnf.matches("ab"));
        assert!(!cnf.matches(""));
        assert!(!Confirmation { jkt: String::new() }.matches(""));
    }

    #[test]
    fn test_oidc_claims_cnf_is_omitted_when_unbound_and_roundtrips() {
        let mut claims: OidcAccessTokenClaims = serde_json::from_value(serde_json::json!({
            "iss": "i", "sub": "s", "aud": "a", "exp": 2, "iat": 1, "nbf": 1,
            "jti": "j", "scope": "openid", "token_use": "access"
        }))
        .unwrap();
        assert!(claims.cnf.is_none());
        assert!(serde_json::to_value(&claims).unwrap().get("cnf").is_none());

        claims.cnf = Some(Confirmation {
            jkt: "thumb".into(),
        });
        let value = serde_json::to_value(&claims).unwrap();
        assert_eq!(value["cnf"], serde_json::json!({"jkt": "thumb"}));
        let back: OidcAccessTokenClaims = serde_json::from_value(value).unwrap();
        assert_eq!(
            back.cnf,
            Some(Confirmation {
                jkt: "thumb".into()
            })
        );
    }

    #[test]
    fn test_plain_delegation_context_serializes_without_project_id() {
        let value = serde_json::to_value(DelegationContext::Plain).unwrap();
        assert_eq!(value, serde_json::json!({"auth_method": "plain"}));
    }

    #[test]
    fn test_openstack_scope_project_tag_is_scope_type() {
        let scope = OpenStackScope::Project {
            project_id: "p1".to_string(),
            project_domain_id: "d1".to_string(),
            roles: vec![],
        };
        let value = serde_json::to_value(&scope).unwrap();
        assert_eq!(value["scope_type"], "project");
        assert_eq!(value["project_id"], "p1");
    }

    #[test]
    fn test_openstack_access_token_claims_flattens_context() {
        let claims = OpenStackAccessTokenClaims {
            iss: "https://ks.example/v4/oauth2/d1".to_string(),
            sub: "shadow-user".to_string(),
            aud: Audience::control_plane(),
            client_id: "client-1".to_string(),
            exp: 1000,
            iat: 900,
            nbf: 900,
            jti: "jti-1".to_string(),
            keystone_ruleset_version: 42,
            amr: vec!["client_credentials".to_string()],
            token_use: "access".to_string(),
            delegation_context: DelegationContext::Plain,
            act: None,
            openstack_context: OpenStackContext {
                user_id: "shadow-user".to_string(),
                user_name: "client-1".to_string(),
                user_domain_id: None,
                scope: OpenStackScope::Domain {
                    domain_id: "d1".to_string(),
                    roles: vec![],
                },
                roles: vec!["member".to_string()],
            },
            cnf: None,
        };
        let value = serde_json::to_value(&claims).unwrap();
        assert_eq!(value["scope_type"], "domain");
        assert_eq!(value["domain_id"], "d1");
        assert_eq!(value["user_id"], "shadow-user");
        assert!(value.get("openstack_context").is_none());
    }

    #[test]
    fn test_audience_control_plane_serializes_as_string() {
        let value = serde_json::to_value(Audience::control_plane()).unwrap();
        assert_eq!(value, serde_json::json!("openstack-apis"));
    }

    #[test]
    fn test_audience_narrowed_round_trip() {
        assert_eq!(
            Audience::narrowed::<&str>(&[]),
            Audience::control_plane(),
            "no service types keeps the default"
        );
        assert_eq!(
            Audience::narrowed(&["compute"]),
            Audience::One("openstack-apis:compute".to_string())
        );
        let many = Audience::narrowed(&["compute", "network", "compute"]);
        let value = serde_json::to_value(&many).unwrap();
        assert_eq!(
            value,
            serde_json::json!(["openstack-apis:compute", "openstack-apis:network"])
        );
        let back: Audience = serde_json::from_value(value).unwrap();
        assert_eq!(back, many);
        assert!(back.contains("openstack-apis:network"));
        assert!(!back.contains("openstack-apis"));
    }

    #[test]
    fn test_is_openstack_audience() {
        assert!(is_openstack_audience("openstack-apis"));
        assert!(is_openstack_audience("openstack-apis:compute"));
        assert!(!is_openstack_audience("openstack-apis:"));
        assert!(!is_openstack_audience("openstack-apisx"));
        assert!(!is_openstack_audience("client-1"));
    }

    #[test]
    fn test_id_token_claims_flattens_extra_claims() {
        let mut extra_claims = HashMap::new();
        extra_claims.insert("email".to_string(), "user@example.com".into());
        let claims = IdTokenClaims {
            iss: "https://ks.example/v4/oauth2/d1".to_string(),
            sub: "user-1".to_string(),
            aud: "client-1".to_string(),
            exp: 1000,
            iat: 900,
            nbf: 900,
            auth_time: 900,
            nonce: Some("abc".to_string()),
            amr: vec!["pwd".to_string()],
            at_hash: None,
            sid: None,
            token_use: "id".to_string(),
            extra_claims,
        };
        let value = serde_json::to_value(&claims).unwrap();
        assert_eq!(value["email"], "user@example.com");
        assert_eq!(value["token_use"], "id");
        assert!(value.get("extra_claims").is_none());
    }

    #[test]
    fn test_oidc_access_token_claims_aud_is_client_id() {
        let claims = OidcAccessTokenClaims {
            iss: "https://ks.example/v4/oauth2/d1".to_string(),
            sub: "user-1".to_string(),
            aud: "client-1".to_string(),
            exp: 1000,
            iat: 900,
            nbf: 900,
            jti: "jti-1".to_string(),
            scope: "openid profile".to_string(),
            token_use: "access".to_string(),
            family_id: None,
            cnf: None,
        };
        let value = serde_json::to_value(&claims).unwrap();
        assert_eq!(value["aud"], "client-1");
        assert_eq!(value["token_use"], "access");
        assert!(value.get("fid").is_none());

        let with_family = OidcAccessTokenClaims {
            family_id: Some("family-1".to_string()),
            ..claims
        };
        let value = serde_json::to_value(&with_family).unwrap();
        assert_eq!(value["fid"], "family-1");
    }
}
