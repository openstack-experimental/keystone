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
// Crypto inventory: TOK-4; see doc/src/contributor/crypto-inventory.md
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
    Audience, Confirmation, DelegationContext, IdTokenClaims, OPENSTACK_APIS_AUDIENCE,
    OidcAccessTokenClaims, OpenStackAccessTokenClaims, OpenStackScope, openstack_service_audience,
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

    /// The token's `scope` does not contain the scope required by the
    /// endpoint it was presented to (e.g. `openid` for `/userinfo`).
    #[error("token scope does not include `{0}`")]
    InsufficientScope(String),

    /// The token is bound to a DPoP key (`cnf`) but was presented without a
    /// valid proof, e.g. as a `Bearer` credential (ADR 0043 §4).
    #[error("a DPoP-bound token must be presented with a DPoP proof")]
    BoundTokenWithoutProof,

    /// A DPoP proof accompanies a token that carries no `cnf` (ADR 0043 §4).
    #[error("a DPoP proof was presented with a token that is not DPoP-bound")]
    ProofWithoutBoundToken,

    /// The proof key is not the key the token is bound to.
    #[error("the DPoP proof key does not match the token binding")]
    ProofKeyMismatch,

    /// The effective DPoP mode is `required` but the token is not bound.
    #[error("an unbound token is not accepted: DPoP is required")]
    UnboundTokenRejected,
}

/// How an access token reached a resource server: the `Authorization` scheme
/// and, for `DPoP`, the thumbprint of the key of the already verified proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenPresentation<'a> {
    /// `Authorization: Bearer <token>`.
    Bearer,
    /// `Authorization: DPoP <token>`. `proof_jkt` is the thumbprint of the
    /// key of the verified `DPoP` proof, or `None` while no proof has been
    /// verified.
    Dpop {
        /// Thumbprint of the verified proof key.
        proof_jkt: Option<&'a str>,
    },
}

/// Enforce the sender-constraint of an access token against the way it was
/// presented (ADR 0043 §4), after the token itself has been verified.
///
/// * a bound token (`cnf`) is accepted only as `DPoP` with a proof made with
///   the bound key, never as `Bearer`;
/// * a `DPoP` presentation of a token without `cnf` is rejected;
/// * an unbound token is rejected as well when `require_bound` is set (the
///   effective mode is `required`).
///
/// A caller that cannot verify a proof passes [`TokenPresentation::Bearer`],
/// which makes every bound token fail closed.
///
/// # Errors
/// See [`TokenVerificationError`]: `BoundTokenWithoutProof`,
/// `ProofWithoutBoundToken`, `ProofKeyMismatch`, `UnboundTokenRejected`.
pub fn enforce_token_binding(
    cnf: Option<&Confirmation>,
    presentation: TokenPresentation<'_>,
    require_bound: bool,
) -> Result<(), TokenVerificationError> {
    match (cnf, presentation) {
        (
            Some(cnf),
            TokenPresentation::Dpop {
                proof_jkt: Some(jkt),
            },
        ) => {
            if cnf.matches(jkt) {
                Ok(())
            } else {
                Err(TokenVerificationError::ProofKeyMismatch)
            }
        }
        (Some(_), _) => Err(TokenVerificationError::BoundTokenWithoutProof),
        (None, TokenPresentation::Dpop { .. }) => {
            Err(TokenVerificationError::ProofWithoutBoundToken)
        }
        (None, TokenPresentation::Bearer) if require_bound => {
            Err(TokenVerificationError::UnboundTokenRejected)
        }
        (None, TokenPresentation::Bearer) => Ok(()),
    }
}

fn auth_method_str(ctx: &DelegationContext) -> &'static str {
    match ctx {
        DelegationContext::Plain => "plain",
        DelegationContext::Trust { .. } => "trust",
        DelegationContext::AppCred { .. } => "app_cred",
        DelegationContext::Ec2 { .. } => "ec2",
        DelegationContext::ServiceGrant { .. } => "service_grant",
        DelegationContext::OnBehalfOf { .. } => "on_behalf_of",
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
        // Only a delegated subject brings a project boundary (ADR 0036
        // §6.2); a plain one is bounded by live assignments.
        DelegationContext::OnBehalfOf {
            project_id: None, ..
        } => return Ok(()),
        DelegationContext::OnBehalfOf {
            project_id: Some(project_id),
            ..
        } => project_id,
        DelegationContext::Trust { project_id }
        | DelegationContext::AppCred { project_id }
        | DelegationContext::Ec2 { project_id }
        | DelegationContext::ServiceGrant { project_id, .. } => project_id,
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

/// Resolve the decoding key for `token` from `jwks`, after pinning the header
/// `alg` to the operator-configured algorithm (ADR 0026 §3).
///
/// Domain isolation relies on `jwks` being the key set of the issuer the token
/// names: callers pass the JWKS of the issuer they are validating against and
/// never a union of several issuers' keys, so a key of domain A can only
/// verify tokens that are checked against A's `iss`.
fn resolve_decoding_key(
    token: &str,
    jwks: &JwkSet,
    expected_algorithm: SigningAlgorithm,
) -> Result<(Algorithm, DecodingKey), TokenVerificationError> {
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
    Ok((expected_alg, DecodingKey::from_jwk(jwk)?))
}

/// Reject an `iss` that is not in the caller's explicit allowlist.
fn ensure_trusted_issuer(
    iss: &str,
    expected_issuers: &[String],
) -> Result<(), TokenVerificationError> {
    if expected_issuers.iter().any(|i| i == iss) {
        Ok(())
    } else {
        Err(TokenVerificationError::UntrustedIssuer(iss.to_string()))
    }
}

/// Verify an `OpenStackAccessTokenClaims` access token fully offline (ADR
/// 0026 §6), given an already-fetched [`JwkSet`] and JTI revocation set.
///
/// Mirrors the reference `KeystoneNativeJwtMiddleware`'s checks in order:
/// signature (against the operator-configured algorithm only, ADR §3),
/// `aud`/`iss`, structural `token_use`/`openstack_context` presence (via typed
/// deserialization), JTI revocation, then the I2/I3/I5 delegation
/// invariants.
///
/// `jwks` must be the key set of the issuer being validated against, and
/// `expected_issuers` the verifier's explicit issuer allowlist: with a flat
/// `aud`, domain isolation rests on `iss` plus that per-issuer key set (ADR
/// 0026 §5). `service_type` is the verifier's own OpenStack service type; when
/// set, a token narrowed to `openstack-apis:<service_type>` is accepted in
/// addition to the un-narrowed `openstack-apis`.
///
/// # Errors
/// See [`TokenVerificationError`] for each rejection reason.
pub fn verify_openstack_access_token(
    token: &str,
    jwks: &JwkSet,
    expected_algorithm: SigningAlgorithm,
    expected_issuers: &[String],
    service_type: Option<&str>,
    revoked_jtis: &HashSet<String>,
) -> Result<OpenStackAccessTokenClaims, TokenVerificationError> {
    // Accept the control-plane audience, or the audience narrowed to this
    // service's own type. A verifier that does not know its service type
    // accepts only the un-narrowed form (ADR 0036 §7.1).
    let mut accepted_audiences = vec![OPENSTACK_APIS_AUDIENCE.to_string()];
    if let Some(service_type) = service_type {
        accepted_audiences.push(openstack_service_audience(service_type));
    }
    verify_openstack_access_token_inner(
        token,
        jwks,
        expected_algorithm,
        expected_issuers,
        Some(&accepted_audiences),
        revoked_jtis,
    )
}

/// Verify an [`OpenStackAccessTokenClaims`] access token that this
/// Keystone minted and now receives back as a `subject_token` (ADR 0036
/// §6.3), whatever service types its `aud` was narrowed to: narrowing only
/// ever removes reach, so the holder may still renew it. Every other check
/// is that of [`verify_openstack_access_token`].
///
/// # Errors
/// See [`TokenVerificationError`] for each rejection reason.
pub fn verify_openstack_subject_token(
    token: &str,
    jwks: &JwkSet,
    expected_algorithm: SigningAlgorithm,
    expected_issuers: &[String],
    revoked_jtis: &HashSet<String>,
) -> Result<OpenStackAccessTokenClaims, TokenVerificationError> {
    verify_openstack_access_token_inner(
        token,
        jwks,
        expected_algorithm,
        expected_issuers,
        None,
        revoked_jtis,
    )
}

/// Shared body of the OpenStack access token verifiers. `audiences` is the
/// accepted `aud` set; `None` accepts any OpenStack audience (the
/// control plane or a narrowing of it) and nothing else.
fn verify_openstack_access_token_inner(
    token: &str,
    jwks: &JwkSet,
    expected_algorithm: SigningAlgorithm,
    expected_issuers: &[String],
    audiences: Option<&[String]>,
    revoked_jtis: &HashSet<String>,
) -> Result<OpenStackAccessTokenClaims, TokenVerificationError> {
    let (expected_alg, decoding_key) = resolve_decoding_key(token, jwks, expected_algorithm)?;

    let mut validation = Validation::new(expected_alg);
    validation.set_required_spec_claims(&["exp", "iat", "nbf", "iss", "aud", "sub"]);
    match audiences {
        Some(audiences) => validation.set_audience(audiences),
        None => validation.validate_aud = false,
    }
    validation.validate_nbf = true;

    let data = decode::<OpenStackAccessTokenClaims>(token, &decoding_key, &validation)?;
    let claims = data.claims;

    if audiences.is_none() && !claims.aud.is_openstack() {
        return Err(TokenVerificationError::Malformed(
            jsonwebtoken::errors::ErrorKind::InvalidAudience.into(),
        ));
    }

    ensure_trusted_issuer(&claims.iss, expected_issuers)?;

    if claims.token_use != "access" {
        return Err(TokenVerificationError::WrongTokenUse(claims.token_use));
    }

    if revoked_jtis.contains(&claims.jti) {
        return Err(TokenVerificationError::Revoked(claims.jti));
    }

    enforce_delegation_invariants(&claims)?;

    Ok(claims)
}

/// Verify an OIDC access token ([`OidcAccessTokenClaims`]) presented to the
/// `/userinfo` endpoint (OIDC Core §5.3), given an already-fetched
/// [`JwkSet`] and JTI revocation set.
///
/// Enforces the signature (configured algorithm only), `iss` allowlist,
/// `exp`/`nbf`, `token_use == "access"`, `jti` not revoked and the `openid`
/// scope. `aud` is the (unknown to the caller) `client_id`, so it is not
/// validated here: the caller must resolve `claims.aud` to a registered
/// client of the domain. OpenStack access tokens (`aud` ==
/// `openstack-apis` or a service-type narrowing of it) carry no `scope` claim
/// and are therefore structurally rejected.
///
/// # Errors
/// See [`TokenVerificationError`] for each rejection reason.
pub fn verify_oidc_access_token(
    token: &str,
    jwks: &JwkSet,
    expected_algorithm: SigningAlgorithm,
    expected_issuers: &[String],
    revoked_jtis: &HashSet<String>,
) -> Result<OidcAccessTokenClaims, TokenVerificationError> {
    let claims = verify_oidc_access_token_unscoped(
        token,
        jwks,
        expected_algorithm,
        expected_issuers,
        revoked_jtis,
    )?;
    ensure_openid_scope(&claims)?;
    Ok(claims)
}

/// [`verify_oidc_access_token`] without the `openid` scope check.
///
/// For a caller that must establish who may use the token before it says
/// anything about the token's scope: an answer of "valid, but lacks the
/// scope" tells the holder of a stolen DPoP-bound token, who has no key,
/// that the token is live. The caller must run [`ensure_openid_scope`]
/// itself.
///
/// # Errors
/// See [`TokenVerificationError`] for each rejection reason.
pub fn verify_oidc_access_token_unscoped(
    token: &str,
    jwks: &JwkSet,
    expected_algorithm: SigningAlgorithm,
    expected_issuers: &[String],
    revoked_jtis: &HashSet<String>,
) -> Result<OidcAccessTokenClaims, TokenVerificationError> {
    let (expected_alg, decoding_key) = resolve_decoding_key(token, jwks, expected_algorithm)?;

    let mut validation = Validation::new(expected_alg);
    validation.set_required_spec_claims(&["exp", "iat", "nbf", "iss", "aud", "sub"]);
    validation.validate_aud = false;
    validation.validate_nbf = true;

    let claims = decode::<OidcAccessTokenClaims>(token, &decoding_key, &validation)?.claims;

    ensure_trusted_issuer(&claims.iss, expected_issuers)?;
    if claims.token_use != "access" {
        return Err(TokenVerificationError::WrongTokenUse(claims.token_use));
    }
    if revoked_jtis.contains(&claims.jti) {
        return Err(TokenVerificationError::Revoked(claims.jti));
    }

    Ok(claims)
}

/// Require the `openid` scope of an OIDC access token.
///
/// # Errors
/// [`TokenVerificationError::InsufficientScope`] when it is missing.
pub fn ensure_openid_scope(claims: &OidcAccessTokenClaims) -> Result<(), TokenVerificationError> {
    if claims.scope.split_whitespace().any(|s| s == "openid") {
        Ok(())
    } else {
        Err(TokenVerificationError::InsufficientScope(
            "openid".to_string(),
        ))
    }
}

/// Verify an `id_token` presented as `id_token_hint` (OIDC RP-Initiated
/// Logout 1.0 §2), given an already-fetched [`JwkSet`].
///
/// Enforces the signature, the configured algorithm, the `iss` allowlist and
/// `token_use == "id"`. Expiry is deliberately **not** enforced: a hint is
/// expected to be a token the OP issued earlier, usually long expired by the
/// time the user logs out. `aud` is the relying party, which the caller must
/// resolve to a registered client of the domain.
///
/// # Errors
/// See [`TokenVerificationError`].
pub fn verify_id_token_hint(
    token: &str,
    jwks: &JwkSet,
    expected_algorithm: SigningAlgorithm,
    expected_issuers: &[String],
) -> Result<IdTokenClaims, TokenVerificationError> {
    let (expected_alg, decoding_key) = resolve_decoding_key(token, jwks, expected_algorithm)?;

    let mut validation = Validation::new(expected_alg);
    validation.set_required_spec_claims(&["iss", "aud", "sub"]);
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.validate_nbf = false;

    let claims = decode::<IdTokenClaims>(token, &decoding_key, &validation)?.claims;

    ensure_trusted_issuer(&claims.iss, expected_issuers)?;
    if claims.token_use != "id" {
        return Err(TokenVerificationError::WrongTokenUse(claims.token_use));
    }
    Ok(claims)
}

/// Minimal facts about an access token that is eligible for RFC 7009
/// revocation, as returned by [`verify_revocable_access_token`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocableAccessToken {
    /// Token identifier to add to the JTI revocation list.
    pub jti: String,
    /// Token expiry (unix seconds); the revocation entry may be swept after.
    pub exp: i64,
    /// Refresh family (`fid` claim, `sid` on older tokens) that minted the
    /// token, if any.
    pub family_id: Option<String>,
}

#[derive(serde::Deserialize)]
struct RevocableClaims {
    iss: String,
    aud: Audience,
    exp: i64,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    token_use: Option<String>,
    #[serde(default, alias = "sid")]
    fid: Option<String>,
}

/// Verify an access token presented to the RFC 7009 revocation endpoint and
/// extract what is needed to revoke it.
///
/// Accepts both access-token flavours this OP mints: the OIDC access token
/// (`aud` == `client_id`) and the OpenStack access token
/// (`aud` == `openstack-apis` or a narrowing of it, plus a `client_id` claim).
/// In both cases the token must belong to `authenticated_client_id`; the
/// signature, configured algorithm, issuer, `exp`/`nbf` and
/// `token_use == "access"` are enforced exactly as in
/// [`verify_openstack_access_token`]. Tokens without a `jti` (e.g. ID tokens)
/// are rejected with [`TokenVerificationError::WrongTokenUse`].
///
/// # Errors
/// See [`TokenVerificationError`]. The revocation endpoint maps every error
/// to a plain `200` so it is not an oracle.
pub fn verify_revocable_access_token(
    token: &str,
    jwks: &JwkSet,
    expected_algorithm: SigningAlgorithm,
    expected_issuers: &[String],
    authenticated_client_id: &str,
) -> Result<RevocableAccessToken, TokenVerificationError> {
    let (expected_alg, decoding_key) = resolve_decoding_key(token, jwks, expected_algorithm)?;

    // `aud` is the owning `client_id` (OIDC flavour) or an OpenStack audience;
    // which one, and whether it belongs to the caller, is decided below.
    let mut validation = Validation::new(expected_alg);
    validation.set_required_spec_claims(&["exp", "iat", "nbf", "iss", "aud", "sub"]);
    validation.validate_aud = false;
    validation.validate_nbf = true;

    let claims = decode::<RevocableClaims>(token, &decoding_key, &validation)?.claims;

    ensure_trusted_issuer(&claims.iss, expected_issuers)?;

    let token_use = claims.token_use.unwrap_or_default();
    if token_use != "access" {
        return Err(TokenVerificationError::WrongTokenUse(token_use));
    }

    // Ownership: the OIDC flavour is bound by `aud`; the OpenStack flavour
    // by its `client_id` claim.
    let owner = if claims.aud.is_openstack() {
        claims.client_id.as_deref()
    } else {
        match claims.aud.values() {
            [client_id] => Some(client_id.as_str()),
            _ => None,
        }
    };
    if owner != Some(authenticated_client_id) {
        return Err(TokenVerificationError::WrongTokenUse(
            "token belongs to another client".to_string(),
        ));
    }

    let jti = claims
        .jti
        .ok_or_else(|| TokenVerificationError::WrongTokenUse("missing jti".to_string()))?;
    Ok(RevocableAccessToken {
        jti,
        exp: claims.exp,
        family_id: claims.fid,
    })
}

/// An access token accepted by the RFC 7662 introspection endpoint, in the
/// flavour it was minted as.
#[derive(Clone, Debug)]
pub enum IntrospectedAccessToken {
    /// OIDC access token (`aud` is the owning `client_id`), usable only
    /// against `/userinfo`.
    Oidc(OidcAccessTokenClaims),
    /// OpenStack access token (`aud` is `openstack-apis` or a narrowing).
    OpenStack(Box<OpenStackAccessTokenClaims>),
}

/// Verify an access token presented to the RFC 7662 introspection endpoint.
///
/// Unlike [`verify_revocable_access_token`] the token need not belong to the
/// calling client: introspection is for resource servers, which act on tokens
/// minted for other clients. Domain isolation comes from the signature
/// (verified against `jwks`, the domain's own keys) and the pinned issuer.
/// Signature, configured algorithm, issuer, `exp`/`nbf`, `token_use` and the
/// `jti` revocation list are enforced as in [`verify_openstack_access_token`];
/// OpenStack tokens additionally go through the delegation invariants.
///
/// # Errors
/// See [`TokenVerificationError`]. The introspection endpoint maps every
/// error to `{"active": false}` so it is not an oracle.
pub fn verify_introspectable_access_token(
    token: &str,
    jwks: &JwkSet,
    expected_algorithm: SigningAlgorithm,
    expected_issuers: &[String],
    revoked_jtis: &HashSet<String>,
) -> Result<IntrospectedAccessToken, TokenVerificationError> {
    let (expected_alg, decoding_key) = resolve_decoding_key(token, jwks, expected_algorithm)?;

    let mut validation = Validation::new(expected_alg);
    validation.set_required_spec_claims(&["exp", "iat", "nbf", "iss", "aud", "sub"]);
    // The audience is any client of this domain (OIDC flavour) or an OpenStack
    // audience; both are covered by signature (the issuer's own JWKS) + issuer
    // below.
    validation.validate_aud = false;
    validation.validate_nbf = true;

    let common = decode::<RevocableClaims>(token, &decoding_key, &validation)?.claims;
    ensure_trusted_issuer(&common.iss, expected_issuers)?;
    let token_use = common.token_use.unwrap_or_default();
    if token_use != "access" {
        return Err(TokenVerificationError::WrongTokenUse(token_use));
    }
    let jti = common
        .jti
        .ok_or_else(|| TokenVerificationError::WrongTokenUse("missing jti".to_string()))?;
    if revoked_jtis.contains(&jti) {
        return Err(TokenVerificationError::Revoked(jti));
    }

    if common.aud.is_openstack() {
        let claims =
            decode::<OpenStackAccessTokenClaims>(token, &decoding_key, &validation)?.claims;
        enforce_delegation_invariants(&claims)?;
        Ok(IntrospectedAccessToken::OpenStack(Box::new(claims)))
    } else {
        let claims = decode::<OidcAccessTokenClaims>(token, &decoding_key, &validation)?.claims;
        Ok(IntrospectedAccessToken::Oidc(claims))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cnf(jkt: &str) -> Confirmation {
        Confirmation { jkt: jkt.into() }
    }

    #[test]
    fn test_binding_bound_token_needs_its_key() {
        let bound = cnf("key-1");
        let dpop = |jkt| TokenPresentation::Dpop {
            proof_jkt: Some(jkt),
        };
        assert!(enforce_token_binding(Some(&bound), dpop("key-1"), true).is_ok());
        assert!(matches!(
            enforce_token_binding(Some(&bound), dpop("key-2"), false),
            Err(TokenVerificationError::ProofKeyMismatch)
        ));
        assert!(matches!(
            enforce_token_binding(Some(&bound), TokenPresentation::Bearer, false),
            Err(TokenVerificationError::BoundTokenWithoutProof)
        ));
        assert!(matches!(
            enforce_token_binding(
                Some(&bound),
                TokenPresentation::Dpop { proof_jkt: None },
                false
            ),
            Err(TokenVerificationError::BoundTokenWithoutProof)
        ));
    }

    #[test]
    fn test_binding_empty_key_never_matches() {
        assert!(matches!(
            enforce_token_binding(
                Some(&cnf("")),
                TokenPresentation::Dpop {
                    proof_jkt: Some("")
                },
                false
            ),
            Err(TokenVerificationError::ProofKeyMismatch)
        ));
    }

    #[test]
    fn test_binding_unbound_token() {
        assert!(enforce_token_binding(None, TokenPresentation::Bearer, false).is_ok());
        assert!(matches!(
            enforce_token_binding(None, TokenPresentation::Bearer, true),
            Err(TokenVerificationError::UnboundTokenRejected)
        ));
        assert!(matches!(
            enforce_token_binding(
                None,
                TokenPresentation::Dpop {
                    proof_jkt: Some("key-1")
                },
                false
            ),
            Err(TokenVerificationError::ProofWithoutBoundToken)
        ));
    }
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
            aud: Audience::control_plane(),
            client_id: "client-1".to_string(),
            exp: now + 900,
            iat: now,
            nbf: now,
            jti: "jti-1".to_string(),
            keystone_ruleset_version: 1,
            amr: vec!["client_credentials".to_string()],
            token_use: "access".to_string(),
            delegation_context: DelegationContext::Plain,
            act: None,
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
            cnf: None,
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

    fn oidc_claims(now: i64) -> OidcAccessTokenClaims {
        OidcAccessTokenClaims {
            iss: ISSUER.to_string(),
            sub: "user-1".to_string(),
            aud: "client-1".to_string(),
            exp: now + 900,
            iat: now,
            nbf: now,
            jti: "jti-1".to_string(),
            scope: "openid profile".to_string(),
            token_use: "access".to_string(),
            family_id: None,
            cnf: None,
        }
    }

    fn verify_oidc(
        token: &str,
        jwks: &JwkSet,
        revoked: &[&str],
    ) -> Result<OidcAccessTokenClaims, TokenVerificationError> {
        verify_oidc_access_token(
            token,
            jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            &revoked.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn test_oidc_access_token_ok() {
        let (token, jwks, _) = sign(&oidc_claims(chrono::Utc::now().timestamp()));
        let claims = verify_oidc(&token, &jwks, &[]).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.aud, "client-1");
    }

    #[test]
    fn test_oidc_access_token_expired() {
        let (token, jwks, _) = sign(&oidc_claims(chrono::Utc::now().timestamp() - 7200));
        assert!(matches!(
            verify_oidc(&token, &jwks, &[]),
            Err(TokenVerificationError::Malformed(_))
        ));
    }

    #[test]
    fn test_oidc_access_token_revoked() {
        let (token, jwks, _) = sign(&oidc_claims(chrono::Utc::now().timestamp()));
        assert!(matches!(
            verify_oidc(&token, &jwks, &["jti-1"]),
            Err(TokenVerificationError::Revoked(_))
        ));
    }

    #[test]
    fn test_oidc_access_token_wrong_issuer_and_token_use() {
        let now = chrono::Utc::now().timestamp();
        let mut claims = oidc_claims(now);
        claims.iss = "https://evil.example/v4/oauth2/domain-1".to_string();
        let (token, jwks, _) = sign(&claims);
        assert!(matches!(
            verify_oidc(&token, &jwks, &[]),
            Err(TokenVerificationError::UntrustedIssuer(_))
        ));

        let mut claims = oidc_claims(now);
        claims.token_use = "id".to_string();
        let (token, jwks, _) = sign(&claims);
        assert!(matches!(
            verify_oidc(&token, &jwks, &[]),
            Err(TokenVerificationError::WrongTokenUse(_))
        ));
    }

    #[test]
    fn test_oidc_access_token_requires_openid_scope() {
        let mut claims = oidc_claims(chrono::Utc::now().timestamp());
        claims.scope = "profile email".to_string();
        let (token, jwks, _) = sign(&claims);
        assert!(matches!(
            verify_oidc(&token, &jwks, &[]),
            Err(TokenVerificationError::InsufficientScope(_))
        ));
    }

    #[test]
    fn test_oidc_access_token_rejects_openstack_token() {
        let (token, jwks, _) = sign(&valid_claims(chrono::Utc::now().timestamp()));
        assert!(matches!(
            verify_oidc(&token, &jwks, &[]),
            Err(TokenVerificationError::Malformed(_))
        ));
    }

    #[test]
    fn test_oidc_access_token_foreign_key() {
        let now = chrono::Utc::now().timestamp();
        let (token, _, _) = sign(&oidc_claims(now));
        let (_, other_jwks, _) = sign(&oidc_claims(now));
        assert!(matches!(
            verify_oidc(&token, &other_jwks, &[]),
            Err(TokenVerificationError::UnknownKeyId(_))
        ));
    }

    #[test]
    fn test_revocable_openstack_token_owned_by_client() {
        let now = chrono::Utc::now().timestamp();
        let claims = valid_claims(now);
        let (token, jwks, _kid) = sign(&claims);
        let got = verify_revocable_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            "client-1",
        )
        .unwrap();
        assert_eq!(got.jti, "jti-1");
        assert_eq!(got.exp, claims.exp);
    }

    #[test]
    fn test_revocable_foreign_client_rejected() {
        let now = chrono::Utc::now().timestamp();
        let (token, jwks, _kid) = sign(&valid_claims(now));
        let err = verify_revocable_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            "client-2",
        )
        .unwrap_err();
        assert!(matches!(err, TokenVerificationError::WrongTokenUse(_)));
    }

    #[test]
    fn test_revocable_oidc_token_owned_by_aud() {
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": ISSUER, "sub": "u", "aud": "client-1", "exp": now + 900,
            "iat": now, "nbf": now, "jti": "jti-oidc", "scope": "openid",
            "token_use": "access", "sid": "family-1",
        });
        let (token, jwks, _kid) = sign(&claims);
        let got = verify_revocable_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            "client-1",
        )
        .unwrap();
        assert_eq!(got.jti, "jti-oidc");
        assert_eq!(got.family_id.as_deref(), Some("family-1"));
    }

    #[test]
    fn test_revocable_token_reads_the_family_from_fid_and_legacy_sid() {
        let now = chrono::Utc::now().timestamp();
        for claim in ["fid", "sid"] {
            let mut claims = serde_json::json!({
                "iss": ISSUER, "sub": "u", "aud": "client-1", "exp": now + 900,
                "iat": now, "nbf": now, "jti": "jti-oidc", "scope": "openid",
                "token_use": "access",
            });
            claims[claim] = "family-1".into();
            let (token, jwks, _kid) = sign(&claims);
            let got = verify_revocable_access_token(
                &token,
                &jwks,
                SigningAlgorithm::Es256,
                &[ISSUER.to_string()],
                "client-1",
            )
            .unwrap();
            assert_eq!(got.family_id.as_deref(), Some("family-1"), "{claim}");
        }
    }

    #[test]
    fn test_revocable_id_token_rejected() {
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": ISSUER, "sub": "u", "aud": "client-1", "exp": now + 900,
            "iat": now, "nbf": now, "token_use": "id",
        });
        let (token, jwks, _kid) = sign(&claims);
        let err = verify_revocable_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            "client-1",
        )
        .unwrap_err();
        assert!(matches!(err, TokenVerificationError::WrongTokenUse(_)));
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
            None,
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
            None,
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(matches!(err, TokenVerificationError::Malformed(_)));
    }

    #[test]
    fn test_wrong_audience_rejected() {
        let now = chrono::Utc::now().timestamp();
        let mut claims = valid_claims(now);
        claims.aud = Audience::One("some-other-service".to_string());
        let (token, jwks, _kid) = sign(&claims);
        let err = verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            None,
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
            None,
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
            sid: None,
            token_use: "id".to_string(),
            extra_claims: Default::default(),
        };
        let (token, jwks, _kid) = sign(&id_claims);
        let err = verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            None,
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
            None,
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
            None,
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

    /// A service grant token (ADR 0036 §5.2) verifies with its `act` claim
    /// and is held to its own project like any delegated token.
    #[test]
    fn test_service_grant_token_round_trip_and_tripwire() {
        let now = chrono::Utc::now().timestamp();
        let mut claims = valid_claims(now);
        claims.delegation_context = DelegationContext::ServiceGrant {
            project_id: "project-1".to_string(),
            grant_id: "g1".to_string(),
        };
        claims.act = Some(openstack_keystone_core_types::oauth2_client::ActClaim {
            client_id: "heat".to_string(),
            sub_type: openstack_keystone_core_types::oauth2_client::ActSubType::Spiffe,
            sub: "spiffe://td/heat".to_string(),
        });
        claims.openstack_context.scope = OpenStackScope::Project {
            project_id: "project-1".to_string(),
            project_domain_id: DOMAIN_ID.to_string(),
            roles: vec![],
        };
        let (token, jwks, _kid) = sign(&claims);
        let verified = verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            None,
            &HashSet::new(),
        )
        .unwrap();
        assert_eq!(verified.act, claims.act);
        assert_eq!(verified.delegation_context, claims.delegation_context);

        claims.openstack_context.scope = OpenStackScope::Project {
            project_id: "project-2".to_string(),
            project_domain_id: DOMAIN_ID.to_string(),
            roles: vec![],
        };
        let (token, jwks, _kid) = sign(&claims);
        assert!(matches!(
            verify_openstack_access_token(
                &token,
                &jwks,
                SigningAlgorithm::Es256,
                &[ISSUER.to_string()],
                None,
                &HashSet::new(),
            ),
            Err(TokenVerificationError::ScopeDrift { .. })
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
            None,
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
            None,
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
            None,
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(matches!(err, TokenVerificationError::UnknownKeyId(_)));
    }

    #[test]
    fn test_introspectable_openstack_token_any_client() {
        let now = chrono::Utc::now().timestamp();
        let (token, jwks, _kid) = sign(&valid_claims(now));
        let got = verify_introspectable_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            &HashSet::new(),
        )
        .unwrap();
        assert!(matches!(got, IntrospectedAccessToken::OpenStack(c) if c.jti == "jti-1"));
    }

    #[test]
    fn test_introspectable_oidc_token() {
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": ISSUER, "sub": "u", "aud": "client-7", "exp": now + 900,
            "iat": now, "nbf": now, "jti": "jti-oidc", "scope": "openid",
            "token_use": "access",
        });
        let (token, jwks, _kid) = sign(&claims);
        let got = verify_introspectable_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            &HashSet::new(),
        )
        .unwrap();
        assert!(matches!(got, IntrospectedAccessToken::Oidc(c) if c.aud == "client-7"));
    }

    #[test]
    fn test_introspectable_revoked_jti_rejected() {
        let now = chrono::Utc::now().timestamp();
        let (token, jwks, _kid) = sign(&valid_claims(now));
        let err = verify_introspectable_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            &HashSet::from(["jti-1".to_string()]),
        )
        .unwrap_err();
        assert!(matches!(err, TokenVerificationError::Revoked(_)));
    }

    #[test]
    fn test_introspectable_untrusted_issuer_rejected() {
        let now = chrono::Utc::now().timestamp();
        let (token, jwks, _kid) = sign(&valid_claims(now));
        let err = verify_introspectable_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &["https://other.example".to_string()],
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(matches!(err, TokenVerificationError::UntrustedIssuer(_)));
    }

    fn verify_for(
        claims: &OpenStackAccessTokenClaims,
        service_type: Option<&str>,
    ) -> Result<OpenStackAccessTokenClaims, TokenVerificationError> {
        let (token, jwks, _kid) = sign(claims);
        verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            service_type,
            &HashSet::new(),
        )
    }

    #[test]
    fn test_retired_domain_bound_audience_rejected() {
        let mut claims = valid_claims(chrono::Utc::now().timestamp());
        claims.aud = Audience::One(format!("openstack-apis:{DOMAIN_ID}"));
        assert!(matches!(
            verify_for(&claims, None),
            Err(TokenVerificationError::Malformed(_))
        ));
        // Not even a service whose type happens to equal the domain id.
        assert!(matches!(
            verify_for(&claims, Some("compute")),
            Err(TokenVerificationError::Malformed(_))
        ));
    }

    #[test]
    fn test_unnarrowed_token_accepted_by_every_service() {
        let claims = valid_claims(chrono::Utc::now().timestamp());
        assert!(verify_for(&claims, None).is_ok());
        assert!(verify_for(&claims, Some("compute")).is_ok());
        assert!(verify_for(&claims, Some("network")).is_ok());
    }

    #[test]
    fn test_narrowed_token_accepted_only_by_matching_service() {
        let mut claims = valid_claims(chrono::Utc::now().timestamp());
        claims.aud = Audience::narrowed(&["compute", "image"]);
        assert!(verify_for(&claims, Some("compute")).is_ok());
        assert!(verify_for(&claims, Some("image")).is_ok());
        assert!(matches!(
            verify_for(&claims, Some("network")),
            Err(TokenVerificationError::Malformed(_))
        ));
        // A service that does not know its type accepts only the
        // un-narrowed form.
        assert!(matches!(
            verify_for(&claims, None),
            Err(TokenVerificationError::Malformed(_))
        ));
    }

    #[test]
    fn test_multi_issuer_service_validates_against_each_issuers_own_jwks() {
        // One service trusting two domains' issuers: each token is verified
        // against the JWKS of the issuer it names, and a domain's key cannot
        // vouch for the other domain's `iss`.
        let now = chrono::Utc::now().timestamp();
        let issuer_a = "https://ks.example/v4/oauth2/domain-a".to_string();
        let issuer_b = "https://ks.example/v4/oauth2/domain-b".to_string();
        let allowlist = [issuer_a.clone(), issuer_b.clone()];

        let claims_for = |iss: String, domain: &str| {
            let mut claims = valid_claims(now);
            claims.iss = iss;
            claims.openstack_context.scope = OpenStackScope::Domain {
                domain_id: domain.to_string(),
                roles: vec![],
            };
            claims
        };
        let (token_a, jwks_a, _) = sign(&claims_for(issuer_a, "domain-a"));
        let (token_b, jwks_b, _) = sign(&claims_for(issuer_b, "domain-b"));

        let verify = |token: &str, jwks: &JwkSet| {
            verify_openstack_access_token(
                token,
                jwks,
                SigningAlgorithm::Es256,
                &allowlist,
                Some("compute"),
                &HashSet::new(),
            )
        };
        assert!(verify(&token_a, &jwks_a).is_ok());
        assert!(verify(&token_b, &jwks_b).is_ok());
        // Domain A's token against domain B's key set: no matching `kid`.
        assert!(matches!(
            verify(&token_a, &jwks_b),
            Err(TokenVerificationError::UnknownKeyId(_))
        ));
    }

    #[test]
    fn test_issuer_outside_allowlist_rejected_despite_valid_signature() {
        // A (compromised) domain key signs a token naming an issuer the
        // service does not trust.
        let mut claims = valid_claims(chrono::Utc::now().timestamp());
        claims.iss = "https://ks.example/v4/oauth2/domain-evil".to_string();
        assert!(matches!(
            verify_for(&claims, Some("compute")),
            Err(TokenVerificationError::UntrustedIssuer(_))
        ));
    }

    #[test]
    fn test_revocable_narrowed_openstack_token_owned_by_client() {
        let mut claims = valid_claims(chrono::Utc::now().timestamp());
        claims.aud = Audience::narrowed(&["compute"]);
        let (token, jwks, _kid) = sign(&claims);
        let got = verify_revocable_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            "client-1",
        )
        .unwrap();
        assert_eq!(got.jti, "jti-1");
    }

    #[test]
    fn test_revocable_mixed_audience_rejected() {
        // `aud` mixing the control-plane value with a client id is neither
        // flavour; the token cannot be claimed through either path.
        let mut claims = valid_claims(chrono::Utc::now().timestamp());
        claims.aud = Audience::Many(vec!["openstack-apis".to_string(), "client-2".to_string()]);
        let (token, jwks, _kid) = sign(&claims);
        let err = verify_revocable_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            "client-2",
        )
        .unwrap_err();
        assert!(matches!(err, TokenVerificationError::WrongTokenUse(_)));
    }

    #[test]
    fn test_introspectable_narrowed_openstack_token() {
        let mut claims = valid_claims(chrono::Utc::now().timestamp());
        claims.aud = Audience::narrowed(&["compute", "network"]);
        let (token, jwks, _kid) = sign(&claims);
        let got = verify_introspectable_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            &HashSet::new(),
        )
        .unwrap();
        assert!(matches!(got, IntrospectedAccessToken::OpenStack(c) if c.jti == "jti-1"));
    }

    #[test]
    fn test_scope_is_independent_of_issuer_domain() {
        // The token proves who; the domain in `iss` does not constrain the
        // scope. A cross-domain grant (user of one domain, project of
        // another) and system scope both verify.
        let mut claims = valid_claims(chrono::Utc::now().timestamp());
        if let OpenStackScope::Project {
            project_domain_id, ..
        } = &mut claims.openstack_context.scope
        {
            *project_domain_id = "domain-b".to_string();
        }
        assert!(verify_for(&claims, Some("compute")).is_ok());

        claims.openstack_context.scope = OpenStackScope::Domain {
            domain_id: "domain-b".to_string(),
            roles: vec![],
        };
        assert!(verify_for(&claims, None).is_ok());

        claims.openstack_context.scope = OpenStackScope::System {
            system_id: "all".to_string(),
            roles: vec![],
        };
        assert!(verify_for(&claims, None).is_ok());

        claims.openstack_context.scope = OpenStackScope::Unscoped;
        assert!(verify_for(&claims, None).is_ok());
    }

    fn id_claims(now: i64, token_use: &str) -> IdTokenClaims {
        IdTokenClaims {
            iss: ISSUER.to_string(),
            sub: "user-1".to_string(),
            aud: "client-1".to_string(),
            exp: now - 3600,
            iat: now - 4500,
            nbf: now - 4500,
            auth_time: now - 4500,
            nonce: None,
            amr: vec!["pwd".to_string()],
            at_hash: None,
            sid: None,
            token_use: token_use.to_string(),
            extra_claims: Default::default(),
        }
    }

    #[test]
    fn test_id_token_hint_accepts_an_expired_id_token() {
        let now = chrono::Utc::now().timestamp();
        let (token, jwks, _kid) = sign(&id_claims(now, "id"));
        let claims = verify_id_token_hint(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
        )
        .unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.aud, "client-1");
    }

    #[test]
    fn test_id_token_hint_rejects_access_tokens_and_foreign_issuers() {
        let now = chrono::Utc::now().timestamp();
        let (token, jwks, _kid) = sign(&id_claims(now, "access"));
        assert!(matches!(
            verify_id_token_hint(
                &token,
                &jwks,
                SigningAlgorithm::Es256,
                &[ISSUER.to_string()]
            ),
            Err(TokenVerificationError::WrongTokenUse(_))
        ));

        let (token, jwks, _kid) = sign(&id_claims(now, "id"));
        assert!(matches!(
            verify_id_token_hint(
                &token,
                &jwks,
                SigningAlgorithm::Es256,
                &["https://other.example".to_string()]
            ),
            Err(TokenVerificationError::UntrustedIssuer(_))
        ));
    }

    #[test]
    fn test_id_token_hint_rejects_a_token_signed_by_another_key() {
        let now = chrono::Utc::now().timestamp();
        let (token, _own_jwks, _kid) = sign(&id_claims(now, "id"));
        let (_other, other_jwks, _kid) = sign(&id_claims(now, "id"));
        assert!(
            verify_id_token_hint(
                &token,
                &other_jwks,
                SigningAlgorithm::Es256,
                &[ISSUER.to_string()]
            )
            .is_err()
        );
    }
}
