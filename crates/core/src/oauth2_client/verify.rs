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
//! # Offline `OpenStackAccessTokenClaims` verification (ADR 0026 §6, §10 Phase 5)
//!
//! Rust-native equivalent of the ADR's `KeystoneNativeJwtMiddleware` Python
//! reference (§6): given an already-fetched [`JwkSet`] and JTI revocation
//! set, verifies an access token fully offline -- no database or network
//! calls beyond what the caller already did to obtain those two inputs. This
//! is the closest in-repo proof of the ADR's Phase 5 claim, since the actual
//! Python WSGI middleware ships in downstream service repos, not here.
//!
//! Deliberately a pure function: it takes the JWKS/revocation set as
//! parameters rather than fetching them itself, so it stays unit-testable
//! without any HTTP or storage mocking. [`crate::oauth2_client`]'s consumers
//! (or `test_integration`) own the fetch-and-cache half of the ADR §6
//! algorithm.
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use std::collections::HashSet;
use thiserror::Error;

use openstack_keystone_core_types::oauth2_client::{
    DelegationContext, OpenStackAccessTokenClaims, OpenStackScope,
};
use openstack_keystone_key_repository::asymmetric::{SigningAlgorithm, jwt_algorithm};

/// Failure modes for offline [`OpenStackAccessTokenClaims`] verification.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TokenVerificationError {
    /// The token's `alg` header does not match the operator-configured
    /// `[oauth2] signing_algorithm`. Rejected before key lookup to prevent
    /// cross-algorithm signature confusion (ADR 0026 §3).
    #[error("token alg {actual:?} does not match configured algorithm {expected:?}")]
    AlgorithmMismatch {
        /// The algorithm the token header claims.
        actual: Algorithm,
        /// The operator-configured algorithm.
        expected: Algorithm,
    },

    /// Delegated auth (`auth_method != "plain"`) must be project-scoped
    /// (security.md I5); this token is scoped otherwise.
    #[error(
        "delegated auth_method `{auth_method}` requires project scope, got `{scope_type}` (I5)"
    )]
    DelegatedScopeNotProject {
        /// The delegated auth method (`trust`, `app_cred`, or `ec2`).
        auth_method: String,
        /// The token's actual `scope_type`.
        scope_type: String,
    },

    /// Cryptographic or structural decode failure: bad signature, expired,
    /// not-yet-valid, wrong `aud`, missing required claim, or a claim shape
    /// that does not match [`OpenStackAccessTokenClaims`] (which -- since
    /// `id_token`/`OidcAccessTokenClaims` carry none of `openstack_context`'s
    /// fields -- is how a non-access-token is structurally rejected without
    /// a separate presence check, mirroring the ADR §6 middleware's Finding
    /// 1.4 check by construction rather than by hand).
    #[error("token failed verification: {0}")]
    Malformed(#[from] jsonwebtoken::errors::Error),

    /// The token header carries no `kid` -- every OP-issued token has one
    /// (ADR 0026 §3), so this always indicates a foreign/malformed token.
    #[error("token header has no `kid`")]
    MissingKeyId,

    /// `jti` appears in the supplied revocation set (ADR 0026 §3 Emergency
    /// Rotation, §11).
    #[error("jti `{0}` has been revoked")]
    Revoked(String),

    /// Scope-drift tripwire (security.md I3): the token's project scope
    /// does not match its own `delegated_project_id`.
    #[error(
        "scope-drift detected: token project_id `{token_project_id}` != delegated_project_id `{delegated_project_id}` (I3)"
    )]
    ScopeDrift {
        /// `project_id` carried by the token's `openstack_context.scope`.
        token_project_id: String,
        /// `delegated_project_id` carried by the token's `delegation_context`.
        delegated_project_id: String,
    },

    /// No JWK in the supplied set matches the token's `kid`.
    #[error("no JWK found for kid `{0}`")]
    UnknownKeyId(String),

    /// `iss` claim value is not in the caller's explicit issuer allowlist.
    /// Claim *presence* is enforced by `Validation::set_required_spec_claims`
    /// above; this is the separate *value* check the ADR §6 pseudocode notes
    /// `jwt.decode`'s `require` option does not perform.
    #[error("issuer `{0}` is not in the configured allowlist")]
    UntrustedIssuer(String),

    /// `token_use` is not `"access"`. Belt-and-suspenders alongside the
    /// structural rejection above (ADR §6 step 4).
    #[error("token_use `{0}` is not `access`")]
    WrongTokenUse(String),
}

fn auth_method_str(ctx: &DelegationContext) -> &'static str {
    match ctx {
        DelegationContext::Plain => "plain",
        DelegationContext::Trust { .. } => "trust",
        DelegationContext::AppCred { .. } => "app_cred",
        DelegationContext::Ec2 { .. } => "ec2",
    }
}

fn scope_type_str(scope: &OpenStackScope) -> &'static str {
    match scope {
        OpenStackScope::Project { .. } => "project",
        OpenStackScope::Domain { .. } => "domain",
        OpenStackScope::System { .. } => "system",
        OpenStackScope::Unscoped => "unscoped",
    }
}

/// Enforce the delegation invariants (security.md I2, I3, I5) an
/// `OpenStackAccessTokenClaims` must satisfy, mirroring the ADR §6
/// middleware's step 7. I2 (a `plain` auth method cannot carry a
/// `delegated_project_id`) is enforced structurally by the
/// [`DelegationContext`] enum shape and needs no runtime check here.
fn enforce_delegation_invariants(
    claims: &OpenStackAccessTokenClaims,
) -> Result<(), TokenVerificationError> {
    let delegated_project_id = match &claims.delegation_context {
        DelegationContext::Plain => return Ok(()),
        DelegationContext::Trust { project_id }
        | DelegationContext::AppCred { project_id }
        | DelegationContext::Ec2 { project_id } => project_id,
    };

    let OpenStackScope::Project {
        project_id: token_project_id,
        ..
    } = &claims.openstack_context.scope
    else {
        return Err(TokenVerificationError::DelegatedScopeNotProject {
            auth_method: auth_method_str(&claims.delegation_context).to_string(),
            scope_type: scope_type_str(&claims.openstack_context.scope).to_string(),
        });
    };

    if token_project_id != delegated_project_id {
        return Err(TokenVerificationError::ScopeDrift {
            token_project_id: token_project_id.clone(),
            delegated_project_id: delegated_project_id.clone(),
        });
    }

    Ok(())
}

/// Verify an `OpenStackAccessTokenClaims` access token fully offline (ADR
/// 0026 §6), given an already-fetched [`JwkSet`] and JTI revocation set.
///
/// Mirrors the reference `KeystoneNativeJwtMiddleware`'s checks in order:
/// signature (against the operator-configured algorithm only, ADR §3),
/// `aud`/`iss`, structural `token_use`/`openstack_context` presence (via
/// typed deserialization), JTI revocation, then the I2/I3/I5 delegation
/// invariants.
///
/// # Errors
/// See [`TokenVerificationError`] for each rejection reason.
pub fn verify_openstack_access_token(
    token: &str,
    jwks: &JwkSet,
    expected_algorithm: SigningAlgorithm,
    expected_issuers: &[String],
    domain_id: &str,
    revoked_jtis: &HashSet<String>,
) -> Result<OpenStackAccessTokenClaims, TokenVerificationError> {
    let header = decode_header(token)?;
    let expected_alg = jwt_algorithm(expected_algorithm);
    if header.alg != expected_alg {
        return Err(TokenVerificationError::AlgorithmMismatch {
            actual: header.alg,
            expected: expected_alg,
        });
    }

    let kid = header.kid.ok_or(TokenVerificationError::MissingKeyId)?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| TokenVerificationError::UnknownKeyId(kid.clone()))?;
    let decoding_key = DecodingKey::from_jwk(jwk)?;

    let expected_audience = format!("openstack-apis:{domain_id}");
    let mut validation = Validation::new(expected_alg);
    validation.set_required_spec_claims(&["exp", "iat", "nbf", "iss", "aud", "sub"]);
    validation.set_audience(&[expected_audience]);
    validation.validate_nbf = true;

    let data = decode::<OpenStackAccessTokenClaims>(token, &decoding_key, &validation)?;
    let claims = data.claims;

    if !expected_issuers.iter().any(|iss| iss == &claims.iss) {
        return Err(TokenVerificationError::UntrustedIssuer(claims.iss));
    }

    if claims.token_use != "access" {
        return Err(TokenVerificationError::WrongTokenUse(claims.token_use));
    }

    if revoked_jtis.contains(&claims.jti) {
        return Err(TokenVerificationError::Revoked(claims.jti));
    }

    enforce_delegation_invariants(&claims)?;

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use openstack_keystone_core_types::oauth2_client::{
        IdTokenClaims, OpenStackContext, OpenStackScope,
    };
    use openstack_keystone_core_types::role::RoleRef;
    use openstack_keystone_key_repository::asymmetric::{generate_keypair, to_encoding_key};

    const DOMAIN_ID: &str = "domain-1";
    const ISSUER: &str = "https://ks.example/v4/oauth2/domain-1";

    fn valid_claims(now: i64) -> OpenStackAccessTokenClaims {
        OpenStackAccessTokenClaims {
            iss: ISSUER.to_string(),
            sub: "shadow-user".to_string(),
            aud: format!("openstack-apis:{DOMAIN_ID}"),
            client_id: "client-1".to_string(),
            exp: now + 900,
            iat: now,
            nbf: now,
            jti: "jti-1".to_string(),
            keystone_ruleset_version: 1,
            amr: vec!["client_credentials".to_string()],
            token_use: "access".to_string(),
            delegation_context: DelegationContext::Plain,
            openstack_context: OpenStackContext {
                user_id: "shadow-user".to_string(),
                user_name: "client-1".to_string(),
                user_domain_id: None,
                scope: OpenStackScope::Project {
                    project_id: "project-1".to_string(),
                    project_domain_id: DOMAIN_ID.to_string(),
                    roles: vec![RoleRef {
                        domain_id: None,
                        id: "role-1".to_string(),
                        name: Some("member".to_string()),
                    }],
                },
                roles: vec!["member".to_string()],
            },
        }
    }

    /// Sign `claims` with a fresh ES256 keypair and return `(token, jwks,
    /// kid)` -- the harness every test in this module builds on.
    fn sign(claims: &impl serde::Serialize) -> (String, JwkSet, String) {
        let material = generate_keypair(SigningAlgorithm::Es256).unwrap();
        let encoding_key: EncodingKey = to_encoding_key(&material).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(material.kid.clone());
        let token = encode(&header, claims, &encoding_key).unwrap();
        let jwk = crate::oauth2_key::jwks::active_keys_to_jwk_set(
            &openstack_keystone_key_repository::asymmetric::ActiveKeys {
                primary: material.clone(),
                previous: None,
            },
        )
        .unwrap();
        (token, jwk, material.kid)
    }

    #[test]
    fn test_valid_token_verifies() {
        let now = chrono::Utc::now().timestamp();
        let (token, jwks, _kid) = sign(&valid_claims(now));
        let result = verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            DOMAIN_ID,
            &HashSet::new(),
        );
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(result.unwrap().sub, "shadow-user");
    }

    #[test]
    fn test_expired_token_rejected() {
        let now = chrono::Utc::now().timestamp();
        let mut claims = valid_claims(now);
        claims.exp = now - 1000;
        claims.iat = now - 2000;
        claims.nbf = now - 2000;
        let (token, jwks, _kid) = sign(&claims);
        let err = verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            DOMAIN_ID,
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(matches!(err, TokenVerificationError::Malformed(_)));
    }

    #[test]
    fn test_wrong_audience_rejected() {
        let now = chrono::Utc::now().timestamp();
        let mut claims = valid_claims(now);
        claims.aud = "openstack-apis:other-domain".to_string();
        let (token, jwks, _kid) = sign(&claims);
        let err = verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            DOMAIN_ID,
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(matches!(err, TokenVerificationError::Malformed(_)));
    }

    #[test]
    fn test_untrusted_issuer_rejected() {
        let now = chrono::Utc::now().timestamp();
        let claims = valid_claims(now);
        let (token, jwks, _kid) = sign(&claims);
        let err = verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &["https://someone-else.example/v4/oauth2/domain-1".to_string()],
            DOMAIN_ID,
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(matches!(err, TokenVerificationError::UntrustedIssuer(iss) if iss == ISSUER));
    }

    #[test]
    fn test_id_token_structurally_rejected() {
        // An `IdTokenClaims` carries none of `OpenStackAccessTokenClaims`'s
        // required fields (no `openstack_context`/`scope_type`/`jti`/etc.),
        // so it fails to deserialize into the access-token type entirely --
        // the structural rejection the ADR §6 middleware's Finding 1.4 check
        // performs by hand, done here by the type system.
        let now = chrono::Utc::now().timestamp();
        let id_claims = IdTokenClaims {
            iss: ISSUER.to_string(),
            sub: "user-1".to_string(),
            aud: "client-1".to_string(),
            exp: now + 900,
            iat: now,
            nbf: now,
            auth_time: now,
            nonce: None,
            amr: vec!["pwd".to_string()],
            at_hash: None,
            token_use: "id".to_string(),
            extra_claims: Default::default(),
        };
        let (token, jwks, _kid) = sign(&id_claims);
        let err = verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            DOMAIN_ID,
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(matches!(err, TokenVerificationError::Malformed(_)));
    }

    #[test]
    fn test_revoked_jti_rejected() {
        let now = chrono::Utc::now().timestamp();
        let claims = valid_claims(now);
        let (token, jwks, _kid) = sign(&claims);
        let mut revoked = HashSet::new();
        revoked.insert("jti-1".to_string());
        let err = verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            DOMAIN_ID,
            &revoked,
        )
        .unwrap_err();
        assert!(matches!(err, TokenVerificationError::Revoked(jti) if jti == "jti-1"));
    }

    #[test]
    fn test_scope_drift_tripwire_trips() {
        let now = chrono::Utc::now().timestamp();
        let mut claims = valid_claims(now);
        claims.delegation_context = DelegationContext::Trust {
            project_id: "project-1".to_string(),
        };
        // Token's own scope claims a *different* project than the
        // delegation it carries -- the exact drift I3 exists to catch.
        claims.openstack_context.scope = OpenStackScope::Project {
            project_id: "project-2".to_string(),
            project_domain_id: DOMAIN_ID.to_string(),
            roles: vec![],
        };
        let (token, jwks, _kid) = sign(&claims);
        let err = verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            DOMAIN_ID,
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TokenVerificationError::ScopeDrift {
                token_project_id,
                delegated_project_id,
            } if token_project_id == "project-2" && delegated_project_id == "project-1"
        ));
    }

    #[test]
    fn test_delegated_non_project_scope_rejected() {
        let now = chrono::Utc::now().timestamp();
        let mut claims = valid_claims(now);
        claims.delegation_context = DelegationContext::Trust {
            project_id: "project-1".to_string(),
        };
        claims.openstack_context.scope = OpenStackScope::Domain {
            domain_id: DOMAIN_ID.to_string(),
            roles: vec![],
        };
        let (token, jwks, _kid) = sign(&claims);
        let err = verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            DOMAIN_ID,
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TokenVerificationError::DelegatedScopeNotProject {
                auth_method,
                scope_type,
            } if auth_method == "trust" && scope_type == "domain"
        ));
    }

    #[test]
    fn test_algorithm_mismatch_rejected() {
        let now = chrono::Utc::now().timestamp();
        let claims = valid_claims(now);
        let (token, jwks, _kid) = sign(&claims);
        let err = verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Rs256,
            &[ISSUER.to_string()],
            DOMAIN_ID,
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TokenVerificationError::AlgorithmMismatch { actual, expected }
            if actual == Algorithm::ES256 && expected == Algorithm::RS256
        ));
    }

    #[test]
    fn test_unknown_kid_rejected() {
        let now = chrono::Utc::now().timestamp();
        let claims = valid_claims(now);
        let (token, _jwks, _kid) = sign(&claims);
        // A JWKS that doesn't contain the signing key at all.
        let other_material = generate_keypair(SigningAlgorithm::Es256).unwrap();
        let other_jwks = crate::oauth2_key::jwks::active_keys_to_jwk_set(
            &openstack_keystone_key_repository::asymmetric::ActiveKeys {
                primary: other_material,
                previous: None,
            },
        )
        .unwrap();
        let err = verify_openstack_access_token(
            &token,
            &other_jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            DOMAIN_ID,
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(matches!(err, TokenVerificationError::UnknownKeyId(_)));
    }
}
