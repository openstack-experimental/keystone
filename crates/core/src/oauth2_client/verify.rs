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
use base64::Engine;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::de::DeserializeOwned;
use std::collections::HashSet;
use std::time::Duration;
use thiserror::Error;

use openstack_keystone_core_types::oauth2_client::is_openstack_audience;
use openstack_keystone_core_types::oauth2_client::{
    Audience, Confirmation, DelegationContext, IdTokenClaims, OPENSTACK_APIS_AUDIENCE,
    OidcAccessTokenClaims, OpenStackAccessTokenClaims, OpenStackScope, openstack_service_audience,
};
use openstack_keystone_key_repository::asymmetric::{SigningAlgorithm, jwt_algorithm};

/// Failure modes for subject-token JWT verification.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TokenVerificationError {
    /// The validation profile is missing required issuer or audience constraints.
    #[error("subject-token validation profile must specify issuers and audiences")]
    InvalidProfile,

    /// The token's `aud` does not satisfy the profile's audience constraint.
    #[error("token audience is not accepted by this profile")]
    InvalidAudience,

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

    /// The token's `alg` header is not one of the algorithms the validation
    /// profile allows. Rejected before key lookup, like
    /// [`Self::AlgorithmMismatch`].
    #[error("token alg {actual:?} is not in the allowed algorithms {allowed:?}")]
    AlgorithmNotAllowed {
        /// The algorithm the token header claims.
        actual: Algorithm,
        /// The algorithms the profile allows.
        allowed: Vec<Algorithm>,
    },

    /// Delegated auth (`auth_method != "plain"`) must be project-scoped
    /// (security.md I5); this token is scoped otherwise.
    #[error(
        "delegated auth_method `{auth_method}` requires project scope, got `{scope_type}` (I5)"
    )]
    DelegatedScopeNotProject {
        /// The delegated auth method (`trust`, `app_cred`, `ec2`, or
        /// `service_grant`).
        auth_method: String,
        /// The token's actual `scope_type`.
        scope_type: String,
    },

    /// Cryptographic or structural decode failure: bad signature, expired,
    /// not-yet-valid, missing required claim, or a claim shape that does not
    /// match [`OpenStackAccessTokenClaims`] (which -- since
    /// `id_token`/`OidcAccessTokenClaims` carry none of `openstack_context`'s
    /// fields -- is how a non-access-token is structurally rejected without
    /// a separate presence check, mirroring the ADR §6 middleware's Finding
    /// 1.4 check by construction rather than by hand).
    #[error("token failed verification: {0}")]
    Malformed(#[from] jsonwebtoken::errors::Error),

    /// The token claims could not be decoded into the requested representation.
    #[error("token claims are malformed: {0}")]
    MalformedClaims(String),

    /// The token header carries no `kid` -- every OP-issued token has one
    /// (ADR 0026 §3), so this always indicates a foreign/malformed token.
    #[error("token header has no `kid`")]
    MissingKeyId,

    /// `jti` appears in the supplied revocation set (ADR 0026 §3 Emergency
    /// Rotation, §11).
    #[error("jti `{0}` has been revoked")]
    Revoked(String),

    /// The token's `iat` is older than the selected validation profile allows.
    #[error("token was issued at {iat}, exceeding the maximum age of {max_age_secs}s")]
    TokenTooOld {
        /// The token's `iat` claim.
        iat: i64,
        /// The profile's maximum token age in seconds.
        max_age_secs: u64,
    },

    /// The token lifetime, or remaining lifetime when it has no `iat`, exceeds
    /// the selected validation profile.
    #[error(
        "token lifetime or remaining lifetime {lifetime_secs}s exceeds the maximum of {max_lifetime_secs}s"
    )]
    TokenLifetimeTooLong {
        /// The token's lifetime, or remaining lifetime, in seconds.
        lifetime_secs: i64,
        /// The profile's maximum lifetime in seconds.
        max_lifetime_secs: u64,
    },

    /// The token's `iat` is ahead of the current time beyond allowed skew.
    #[error("token `iat` is in the future")]
    IssuedInFuture,

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

#[derive(Clone, Debug)]
enum AudienceConstraint {
    AnyOf(Vec<String>),
    Exact(String),
    AnyOpenStack,
}

/// Subject-token verification constraints shared by token-exchange profiles.
///
/// Callers select a profile by token kind and supply the JWKS belonging to the
/// expected issuer. The profile controls issuer and audience constraints,
/// required claims, time skew, and optional age/lifetime limits.
#[derive(Clone, Debug)]
pub struct SubjectTokenValidationProfile {
    expected_issuers: Vec<String>,
    audience_constraint: AudienceConstraint,
    required_claims: Vec<String>,
    string_claims: Vec<String>,
    max_token_age: Option<Duration>,
    max_token_lifetime: Option<Duration>,
    clock_skew: Duration,
    allowed_algorithms: Vec<Algorithm>,
}

const NATIVE_REQUIRED_CLAIMS: &[&str] = &["exp", "iat", "nbf", "iss", "aud", "sub", "jti"];
const EXTERNAL_REQUIRED_CLAIMS: &[&str] = &["exp", "iss", "aud", "sub"];
const ASSERTION_REQUIRED_CLAIMS: &[&str] = &["exp", "iat", "iss", "aud", "sub", "jti"];
const PROFILE_STRING_CLAIMS: &[&str] = &["iss", "sub", "jti"];
const PROFILE_CLOCK_SKEW: Duration = Duration::from_secs(60);
const EXTERNAL_MAX_AGE: Duration = Duration::from_secs(300);
/// Algorithms an external profile allows unless the caller narrows or widens
/// the list with [`SubjectTokenValidationProfile::with_allowed_algorithms`].
const DEFAULT_EXTERNAL_ALGORITHMS: [Algorithm; 2] = [Algorithm::RS256, Algorithm::ES256];

/// Whether `algorithm` is a symmetric (HMAC) algorithm. A profile never
/// allows one: the verifier only holds public keys, so an HMAC "signature"
/// could be forged with the public key as the secret.
fn is_symmetric(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
    )
}

fn owned_claims(claims: &[&str]) -> Vec<String> {
    claims.iter().map(|claim| (*claim).to_string()).collect()
}

impl SubjectTokenValidationProfile {
    fn new(
        expected_issuers: &[String],
        audience_constraint: AudienceConstraint,
        required_claims: &[&str],
        limits: Option<Duration>,
        allowed_algorithms: &[Algorithm],
    ) -> Self {
        Self {
            expected_issuers: expected_issuers.to_vec(),
            audience_constraint,
            required_claims: owned_claims(required_claims),
            string_claims: owned_claims(PROFILE_STRING_CLAIMS),
            max_token_age: limits,
            max_token_lifetime: limits,
            clock_skew: PROFILE_CLOCK_SKEW,
            allowed_algorithms: allowed_algorithms.to_vec(),
        }
    }

    /// Replace the algorithms the profile accepts in the JWT `alg` header.
    ///
    /// Native profiles accept exactly their configured signing algorithm and
    /// external profiles default to RS256 and ES256. Use this to apply the
    /// list configured for an identity provider. An empty list or one that
    /// contains an HMAC algorithm makes verification fail with
    /// [`TokenVerificationError::InvalidProfile`].
    #[must_use]
    pub fn with_allowed_algorithms(mut self, allowed_algorithms: &[Algorithm]) -> Self {
        self.allowed_algorithms = allowed_algorithms.to_vec();
        self
    }

    /// The existing Keystone-native OpenStack access-token profile.
    ///
    /// It preserves acceptance of the control-plane audience and, when
    /// supplied, a token narrowed to this service type. The 60-second skew
    /// matches the verifier's previous `jsonwebtoken` default. Only the
    /// operator-configured `signing_algorithm` is accepted.
    pub fn keystone_native(
        expected_issuers: &[String],
        service_type: Option<&str>,
        signing_algorithm: SigningAlgorithm,
    ) -> Self {
        let mut accepted_audiences = vec![OPENSTACK_APIS_AUDIENCE.to_string()];
        if let Some(service_type) = service_type {
            accepted_audiences.push(openstack_service_audience(service_type));
        }

        Self::new(
            expected_issuers,
            AudienceConstraint::AnyOf(accepted_audiences),
            NATIVE_REQUIRED_CLAIMS,
            None,
            &[jwt_algorithm(signing_algorithm)],
        )
    }

    /// A native OpenStack subject-token profile that accepts any OpenStack
    /// audience, including service-type narrowed audiences. This is for
    /// re-exchanging Keystone-minted tokens; ordinary resource-server
    /// verification should use [`Self::keystone_native`] to enforce its
    /// service audience.
    pub fn keystone_native_subject_token(
        expected_issuers: &[String],
        signing_algorithm: SigningAlgorithm,
    ) -> Self {
        Self::new(
            expected_issuers,
            AudienceConstraint::AnyOpenStack,
            NATIVE_REQUIRED_CLAIMS,
            None,
            &[jwt_algorithm(signing_algorithm)],
        )
    }

    /// A profile for short-lived external subject tokens, including JWT-SVIDs.
    ///
    /// The audience is the exact token-endpoint audience configured by the
    /// caller. If `iat` is present, issuance time may be at most 300 seconds
    /// old and `exp - iat` may not exceed 300 seconds. Without `iat`, the
    /// token must expire within 300 seconds. The age limit is strict and does
    /// not include clock skew; the 60-second skew applies only to registered
    /// time claims and rejecting future `iat`. Replay detection for `jti`,
    /// when present, remains the caller's responsibility.
    pub fn external_assertion(expected_issuers: &[String], token_endpoint_audience: &str) -> Self {
        Self::new(
            expected_issuers,
            AudienceConstraint::Exact(token_endpoint_audience.to_string()),
            EXTERNAL_REQUIRED_CLAIMS,
            Some(EXTERNAL_MAX_AGE),
            &DEFAULT_EXTERNAL_ALGORITHMS,
        )
    }

    /// A JWT-SVID client-assertion profile. Unlike external subject tokens,
    /// client assertions require an issuance time and a replay identifier.
    /// Callers must still record `jti` in a replay cache.
    pub fn jwt_svid_client_assertion(
        expected_issuers: &[String],
        token_endpoint_audience: &str,
    ) -> Self {
        Self::new(
            expected_issuers,
            AudienceConstraint::Exact(token_endpoint_audience.to_string()),
            ASSERTION_REQUIRED_CLAIMS,
            Some(EXTERNAL_MAX_AGE),
            &DEFAULT_EXTERNAL_ALGORITHMS,
        )
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

    Ok((expected_alg, decoding_key_for(header.kid, jwks)?))
}

/// Look up the key a token header names by `kid` in `jwks`.
fn decoding_key_for(
    kid: Option<String>,
    jwks: &JwkSet,
) -> Result<DecodingKey, TokenVerificationError> {
    let kid = kid.ok_or(TokenVerificationError::MissingKeyId)?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| TokenVerificationError::UnknownKeyId(kid.clone()))?;
    Ok(DecodingKey::from_jwk(jwk)?)
}

/// Resolve the decoding key for `token` from `jwks`, after checking the header
/// `alg` against the profile's allowed algorithms.
///
/// The check runs before any key lookup, so a token naming `HS256` (or an
/// algorithm the profile does not list) never reaches signature verification.
/// A profile with exactly one algorithm reports a mismatch with
/// [`TokenVerificationError::AlgorithmMismatch`], as the native profiles
/// always have.
fn resolve_profile_decoding_key(
    token: &str,
    jwks: &JwkSet,
    allowed_algorithms: &[Algorithm],
) -> Result<(Algorithm, DecodingKey), TokenVerificationError> {
    let header = decode_header(token)?;
    if !allowed_algorithms.contains(&header.alg) {
        return Err(match allowed_algorithms {
            [expected] => TokenVerificationError::AlgorithmMismatch {
                actual: header.alg,
                expected: *expected,
            },
            _ => TokenVerificationError::AlgorithmNotAllowed {
                actual: header.alg,
                allowed: allowed_algorithms.to_vec(),
            },
        });
    }

    Ok((header.alg, decoding_key_for(header.kid, jwks)?))
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

/// Verify a signed JWT against a selected subject-token validation profile.
///
/// The supplied JWKS must belong to the expected issuer. This function
/// validates the profile's allowed algorithms, signature, required claims,
/// issuer, audience, registered time claims, and any profile age/lifetime
/// limits. It does not perform JTI replay-cache or revocation checks.
///
/// # Errors
/// Returns [`TokenVerificationError`] when the profile is incomplete or the
/// JWT fails a cryptographic, claim, or time check.
pub fn verify_subject_token_jwt<T>(
    token: &str,
    jwks: &JwkSet,
    profile: &SubjectTokenValidationProfile,
) -> Result<T, TokenVerificationError>
where
    T: DeserializeOwned,
{
    const MANDATORY_CLAIMS: [&str; 3] = ["exp", "iss", "aud"];
    let missing_mandatory_claim = MANDATORY_CLAIMS.iter().any(|claim| {
        !profile
            .required_claims
            .iter()
            .any(|required| required == claim)
    });
    if profile.expected_issuers.is_empty()
        || profile.expected_issuers.iter().any(String::is_empty)
        || profile.allowed_algorithms.is_empty()
        || profile.allowed_algorithms.iter().copied().any(is_symmetric)
        || missing_mandatory_claim
        || match &profile.audience_constraint {
            AudienceConstraint::AnyOf(audiences) => {
                audiences.is_empty() || audiences.iter().any(String::is_empty)
            }
            AudienceConstraint::Exact(audience) => audience.is_empty(),
            AudienceConstraint::AnyOpenStack => false,
        }
    {
        return Err(TokenVerificationError::InvalidProfile);
    }

    let (alg, decoding_key) =
        resolve_profile_decoding_key(token, jwks, &profile.allowed_algorithms)?;
    let mut validation = Validation::new(alg);
    validation.set_required_spec_claims(&profile.required_claims);
    match &profile.audience_constraint {
        AudienceConstraint::AnyOf(audiences) => validation.set_audience(audiences),
        AudienceConstraint::Exact(audience) => {
            validation.set_audience(std::slice::from_ref(audience))
        }
        AudienceConstraint::AnyOpenStack => validation.validate_aud = false,
    }
    validation.validate_nbf = true;
    validation.leeway = profile.clock_skew.as_secs();

    let data =
        decode::<serde_json::Value>(token, &decoding_key, &validation).map_err(
            |error| match error.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                    TokenVerificationError::InvalidAudience
                }
                _ => error.into(),
            },
        )?;
    let claims = data.claims;
    for claim in &profile.required_claims {
        if claims.get(claim).is_none_or(serde_json::Value::is_null) {
            return Err(TokenVerificationError::MalformedClaims(format!(
                "missing required claim `{claim}`"
            )));
        }
    }
    for claim in &profile.string_claims {
        if claims.get(claim).is_some_and(|value| !value.is_string()) {
            return Err(TokenVerificationError::MalformedClaims(format!(
                "claim `{claim}` must be a string"
            )));
        }
    }
    let issuer = claims
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TokenVerificationError::MalformedClaims("missing string `iss`".into()))?;
    ensure_trusted_issuer(issuer, &profile.expected_issuers)?;
    match &profile.audience_constraint {
        AudienceConstraint::AnyOf(_) => {}
        AudienceConstraint::Exact(expected) => {
            let exact_audience = match claims.get("aud") {
                Some(serde_json::Value::String(audience)) => audience == expected,
                Some(serde_json::Value::Array(audiences)) if audiences.len() == 1 => {
                    audiences[0].as_str() == Some(expected)
                }
                _ => false,
            };
            if !exact_audience {
                return Err(TokenVerificationError::InvalidAudience);
            }
        }
        AudienceConstraint::AnyOpenStack => {
            let is_openstack = match claims.get("aud") {
                Some(serde_json::Value::String(audience)) => is_openstack_audience(audience),
                Some(serde_json::Value::Array(audiences)) if !audiences.is_empty() => audiences
                    .iter()
                    .all(|audience| audience.as_str().is_some_and(is_openstack_audience)),
                _ => false,
            };
            if !is_openstack {
                return Err(TokenVerificationError::InvalidAudience);
            }
        }
    }
    validate_profile_time_claims(&claims, profile, chrono::Utc::now().timestamp())?;
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| TokenVerificationError::MalformedClaims("missing JWT payload".into()))?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| TokenVerificationError::MalformedClaims(e.to_string()))?;
    serde_json::from_slice(&payload)
        .map_err(|e| TokenVerificationError::MalformedClaims(e.to_string()))
}

fn validate_profile_time_claims(
    claims: &serde_json::Value,
    profile: &SubjectTokenValidationProfile,
    now: i64,
) -> Result<(), TokenVerificationError> {
    let iat = claims
        .get("iat")
        .map(|value| {
            value.as_i64().ok_or_else(|| {
                TokenVerificationError::MalformedClaims("`iat` must be an integer".into())
            })
        })
        .transpose()?;

    if let Some(iat) = iat {
        if iat > now.saturating_add(profile.clock_skew.as_secs() as i64) {
            return Err(TokenVerificationError::IssuedInFuture);
        }

        if let Some(max_age) = profile.max_token_age
            && now.saturating_sub(iat) > max_age.as_secs() as i64
        {
            return Err(TokenVerificationError::TokenTooOld {
                iat,
                max_age_secs: max_age.as_secs(),
            });
        }
    }

    if let Some(max_lifetime) = profile.max_token_lifetime {
        let exp = claims
            .get("exp")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| {
                TokenVerificationError::MalformedClaims("missing integer `exp`".into())
            })?;
        let lifetime = iat.map_or_else(|| exp.saturating_sub(now), |iat| exp.saturating_sub(iat));
        if lifetime > max_lifetime.as_secs() as i64 {
            return Err(TokenVerificationError::TokenLifetimeTooLong {
                lifetime_secs: lifetime,
                max_lifetime_secs: max_lifetime.as_secs(),
            });
        }
    }

    Ok(())
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
    let profile = SubjectTokenValidationProfile::keystone_native(
        expected_issuers,
        service_type,
        expected_algorithm,
    );
    verify_openstack_access_token_inner(token, jwks, &profile, revoked_jtis)
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
    let profile = SubjectTokenValidationProfile::keystone_native_subject_token(
        expected_issuers,
        expected_algorithm,
    );
    verify_openstack_access_token_inner(token, jwks, &profile, revoked_jtis)
}

/// Apply the selected native-token profile, then enforce access-token-specific
/// revocation and delegation invariants.
fn verify_openstack_access_token_inner(
    token: &str,
    jwks: &JwkSet,
    profile: &SubjectTokenValidationProfile,
    revoked_jtis: &HashSet<String>,
) -> Result<OpenStackAccessTokenClaims, TokenVerificationError> {
    let claims: OpenStackAccessTokenClaims = verify_subject_token_jwt(token, jwks, profile)?;

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
        ActClaim, ActSubType, IdTokenClaims, OpenStackContext, OpenStackScope,
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
        openstack_keystone_jwt_crypto::install().unwrap();
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

    fn assertion_claims(now: i64) -> serde_json::Value {
        serde_json::json!({
            "iss": "https://issuer.example",
            "sub": "subject-1",
            "aud": "https://keystone.example/v4/oauth2/token",
            "exp": now + 300,
            "iat": now,
            "nbf": now,
            "jti": "assertion-1"
        })
    }

    fn verify_assertion(
        claims: &serde_json::Value,
        profile: &SubjectTokenValidationProfile,
    ) -> Result<serde_json::Value, TokenVerificationError> {
        let (token, jwks, _) = sign(claims);
        verify_subject_token_jwt(&token, &jwks, profile)
    }

    /// `iss`/`sub`/`aud` of [`assertion_claims`], as an external profile.
    fn external_profile() -> SubjectTokenValidationProfile {
        SubjectTokenValidationProfile::external_assertion(
            &["https://issuer.example".to_string()],
            "https://keystone.example/v4/oauth2/token",
        )
    }

    /// Sign `claims` with `algorithm` and return `(token, jwks)`. PS256 uses a
    /// fresh RSA key; EdDSA uses the Ed25519 key of RFC 8037 Appendix A.
    fn sign_with_algorithm(
        algorithm: Algorithm,
        claims: &impl serde::Serialize,
    ) -> (String, JwkSet) {
        openstack_keystone_jwt_crypto::install().unwrap();
        match algorithm {
            Algorithm::PS256 => {
                let material = generate_keypair(SigningAlgorithm::Rs256).unwrap();
                let mut header = Header::new(Algorithm::PS256);
                header.kid = Some(material.kid.clone());
                let token = encode(&header, claims, &to_encoding_key(&material).unwrap()).unwrap();
                let jwks = crate::oauth2_key::jwks::active_keys_to_jwk_set(
                    &openstack_keystone_key_repository::asymmetric::ActiveKeys {
                        primary: material,
                        previous: None,
                    },
                )
                .unwrap();
                (token, jwks)
            }
            Algorithm::EdDSA => {
                // RFC 8037 Appendix A.1 test key.
                let seed = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
                    .unwrap();
                // PKCS#8 v2 wrapper of the seed and public key, the form the
                // crypto backend loads.
                let public = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
                    .unwrap();
                let mut der = Vec::from([
                    0x30, 0x53, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
                    0x22, 0x04, 0x20,
                ]);
                der.extend_from_slice(&seed);
                der.extend_from_slice(&[0xa1, 0x23, 0x03, 0x21, 0x00]);
                der.extend_from_slice(&public);
                let mut header = Header::new(Algorithm::EdDSA);
                header.kid = Some("ed-test".to_string());
                let token = encode(&header, claims, &EncodingKey::from_ed_der(&der)).unwrap();
                let jwks: JwkSet = serde_json::from_value(serde_json::json!({
                    "keys": [{
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                        "kid": "ed-test",
                        "alg": "EdDSA",
                        "use": "sig"
                    }]
                }))
                .unwrap();
                (token, jwks)
            }
            other => panic!("unsupported test algorithm {other:?}"),
        }
    }

    #[test]
    fn external_profile_defaults_to_rs256_and_es256() {
        let claims = assertion_claims(chrono::Utc::now().timestamp());
        // ES256 is signed by `sign`; PS256 is outside the default list.
        assert!(verify_assertion(&claims, &external_profile()).is_ok());

        let (token, jwks) = sign_with_algorithm(Algorithm::PS256, &claims);
        assert!(matches!(
            verify_subject_token_jwt::<serde_json::Value>(&token, &jwks, &external_profile()),
            Err(TokenVerificationError::AlgorithmNotAllowed {
                actual: Algorithm::PS256,
                ..
            })
        ));
    }

    #[test]
    fn external_profile_accepts_configured_ps256() {
        let claims = assertion_claims(chrono::Utc::now().timestamp());
        let profile = external_profile().with_allowed_algorithms(&[Algorithm::PS256]);
        let (token, jwks) = sign_with_algorithm(Algorithm::PS256, &claims);
        assert!(matches!(
            verify_subject_token_jwt::<serde_json::Value>(&token, &jwks, &profile),
            Ok(verified) if verified == claims
        ));
    }

    #[test]
    fn external_profile_accepts_configured_eddsa() {
        let claims = assertion_claims(chrono::Utc::now().timestamp());
        let profile = external_profile().with_allowed_algorithms(&[
            Algorithm::RS256,
            Algorithm::ES256,
            Algorithm::EdDSA,
        ]);
        let (token, jwks) = sign_with_algorithm(Algorithm::EdDSA, &claims);
        assert!(matches!(
            verify_subject_token_jwt::<serde_json::Value>(&token, &jwks, &profile),
            Ok(verified) if verified == claims
        ));
    }

    #[test]
    fn external_profile_rejects_algorithm_outside_configured_list() {
        let claims = assertion_claims(chrono::Utc::now().timestamp());
        let profile =
            external_profile().with_allowed_algorithms(&[Algorithm::PS256, Algorithm::EdDSA]);
        // `sign` produces an ES256 token.
        assert!(matches!(
            verify_assertion(&claims, &profile),
            Err(TokenVerificationError::AlgorithmNotAllowed {
                actual: Algorithm::ES256,
                ..
            })
        ));
    }

    #[test]
    fn external_profile_rejects_hs256_token() {
        openstack_keystone_jwt_crypto::install().unwrap();
        let claims = assertion_claims(chrono::Utc::now().timestamp());
        // An attacker signs with HMAC, using public key material as the secret.
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("any".to_string());
        let token = encode(&header, &claims, &EncodingKey::from_secret(b"public-key")).unwrap();
        let (_, jwks, _) = sign(&claims);

        assert!(matches!(
            verify_subject_token_jwt::<serde_json::Value>(&token, &jwks, &external_profile()),
            Err(TokenVerificationError::AlgorithmNotAllowed {
                actual: Algorithm::HS256,
                ..
            })
        ));
    }

    #[test]
    fn external_profile_rejects_alg_none_token() {
        let claims = assertion_claims(chrono::Utc::now().timestamp());
        let (_, jwks, _) = sign(&claims);
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = engine.encode(br#"{"alg":"none","typ":"JWT","kid":"any"}"#);
        let payload = engine.encode(serde_json::to_vec(&claims).unwrap());
        let token = format!("{header}.{payload}.");

        assert!(matches!(
            verify_subject_token_jwt::<serde_json::Value>(&token, &jwks, &external_profile()),
            Err(TokenVerificationError::Malformed(_))
        ));
    }

    #[test]
    fn profile_never_allows_hmac_or_an_empty_list() {
        let claims = assertion_claims(chrono::Utc::now().timestamp());
        for algorithms in [
            &[][..],
            &[Algorithm::HS256][..],
            &[Algorithm::ES256, Algorithm::HS512][..],
        ] {
            let profile = external_profile().with_allowed_algorithms(algorithms);
            assert!(matches!(
                verify_assertion(&claims, &profile),
                Err(TokenVerificationError::InvalidProfile)
            ));
        }
    }

    #[test]
    fn keystone_native_subject_profile_accepts_narrowed_audiences() {
        let profile = SubjectTokenValidationProfile::keystone_native_subject_token(
            &[ISSUER.to_string()],
            SigningAlgorithm::Es256,
        );
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": ISSUER,
            "sub": "subject-1",
            "aud": ["openstack-apis:compute", "openstack-apis:network"],
            "exp": now + 300,
            "iat": now,
            "nbf": now,
            "jti": "native-subject-1"
        });

        assert!(matches!(
            verify_assertion(&claims, &profile),
            Ok(verified) if verified == claims
        ));

        let mut mixed_audience = claims;
        mixed_audience["aud"] = serde_json::json!(["openstack-apis:compute", "unrelated-client"]);
        assert!(matches!(
            verify_assertion(&mixed_audience, &profile),
            Err(TokenVerificationError::InvalidAudience)
        ));
    }

    #[test]
    fn test_openstack_subject_token_accepts_narrowed_openstack_audience() {
        let now = chrono::Utc::now().timestamp();
        let mut claims = valid_claims(now);
        claims.aud = Audience::narrowed(&["compute"]);
        let (token, jwks, _) = sign(&claims);

        assert!(matches!(
            verify_openstack_subject_token(
                &token,
                &jwks,
                SigningAlgorithm::Es256,
                &[ISSUER.to_string()],
                &HashSet::new(),
            ),
            Ok(verified) if verified.aud == claims.aud
        ));

        claims.aud = Audience::Many(vec![
            "openstack-apis:compute".to_string(),
            "unrelated-client".to_string(),
        ]);
        let (token, jwks, _) = sign(&claims);
        assert!(matches!(
            verify_openstack_subject_token(
                &token,
                &jwks,
                SigningAlgorithm::Es256,
                &[ISSUER.to_string()],
                &HashSet::new(),
            ),
            Err(TokenVerificationError::InvalidAudience)
        ));
    }

    #[test]
    fn subject_token_profile_accepts_short_lived_assertion() {
        let profile = SubjectTokenValidationProfile::external_assertion(
            &["https://issuer.example".to_string()],
            "https://keystone.example/v4/oauth2/token",
        );
        let claims = assertion_claims(chrono::Utc::now().timestamp());

        assert!(matches!(
            verify_assertion(&claims, &profile),
            Ok(verified) if verified == claims
        ));
    }

    #[test]
    fn subject_token_profile_accepts_jwt_svid_claims() {
        let profile = SubjectTokenValidationProfile::external_assertion(
            &["https://issuer.example".to_string()],
            "https://keystone.example/v4/oauth2/token",
        );
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": "https://issuer.example",
            "sub": "subject-1",
            "aud": "https://keystone.example/v4/oauth2/token",
            "exp": now + 300
        });

        assert!(matches!(
            verify_assertion(&claims, &profile),
            Ok(verified) if verified == claims
        ));

        let mut long_lived = claims;
        long_lived["exp"] = (now + 301).into();
        assert!(matches!(
            verify_assertion(&long_lived, &profile),
            Err(TokenVerificationError::TokenLifetimeTooLong { .. })
        ));
    }

    #[test]
    fn subject_token_profile_rejects_bad_signature_and_algorithm() {
        let profile = SubjectTokenValidationProfile::external_assertion(
            &["https://issuer.example".to_string()],
            "https://keystone.example/v4/oauth2/token",
        )
        .with_allowed_algorithms(&[Algorithm::RS256]);
        let claims = assertion_claims(chrono::Utc::now().timestamp());
        let (token, jwks, _) = sign(&claims);

        let parts: Vec<_> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header = parts[0];
        let payload = parts[1];
        let signature = parts[2];
        let replacement = if signature.starts_with('A') { 'B' } else { 'A' };
        let tampered = format!("{header}.{payload}.{replacement}{}", &signature[1..]);

        let es256_profile = SubjectTokenValidationProfile::external_assertion(
            &["https://issuer.example".to_string()],
            "https://keystone.example/v4/oauth2/token",
        );
        assert!(matches!(
            verify_subject_token_jwt::<serde_json::Value>(&tampered, &jwks, &es256_profile),
            Err(TokenVerificationError::Malformed(_))
        ));

        assert!(matches!(
            verify_subject_token_jwt::<serde_json::Value>(&token, &jwks, &profile,),
            Err(TokenVerificationError::AlgorithmMismatch { .. })
        ));
    }

    #[test]
    fn subject_token_profile_rejects_untrusted_issuer() {
        let profile = SubjectTokenValidationProfile::external_assertion(
            &["https://issuer.example".to_string()],
            "https://keystone.example/v4/oauth2/token",
        );
        let mut claims = assertion_claims(chrono::Utc::now().timestamp());
        claims["iss"] = "https://untrusted.example".into();

        assert!(matches!(
            verify_assertion(&claims, &profile),
            Err(TokenVerificationError::UntrustedIssuer(_))
        ));
    }

    #[test]
    fn subject_token_profile_requires_exact_endpoint_audience() {
        let profile = SubjectTokenValidationProfile::external_assertion(
            &["https://issuer.example".to_string()],
            "https://keystone.example/v4/oauth2/token",
        );
        let now = chrono::Utc::now().timestamp();

        let mut wrong_audience = assertion_claims(now);
        wrong_audience["aud"] = "https://other.example/token".into();
        assert!(matches!(
            verify_assertion(&wrong_audience, &profile),
            Err(TokenVerificationError::InvalidAudience)
        ));

        let mut extra_audience = assertion_claims(now);
        extra_audience["aud"] = serde_json::json!([
            "https://keystone.example/v4/oauth2/token",
            "https://other.example/token"
        ]);
        assert!(matches!(
            verify_assertion(&extra_audience, &profile),
            Err(TokenVerificationError::InvalidAudience)
        ));
    }

    #[test]
    fn subject_token_profile_does_not_require_jti() {
        let profile = SubjectTokenValidationProfile::external_assertion(
            &["https://issuer.example".to_string()],
            "https://keystone.example/v4/oauth2/token",
        );
        let mut claims = assertion_claims(chrono::Utc::now().timestamp());
        assert!(
            claims
                .as_object_mut()
                .is_some_and(|object| object.remove("jti").is_some())
        );

        assert!(matches!(
            verify_assertion(&claims, &profile),
            Ok(verified) if verified == claims
        ));
    }

    #[test]
    fn jwt_svid_client_assertion_profile_requires_jti_and_iat() {
        let profile = SubjectTokenValidationProfile::jwt_svid_client_assertion(
            &["https://issuer.example".to_string()],
            "https://keystone.example/v4/oauth2/token",
        );
        let mut claims = assertion_claims(chrono::Utc::now().timestamp());
        assert!(verify_assertion(&claims, &profile).is_ok());

        assert!(
            claims
                .as_object_mut()
                .is_some_and(|object| object.remove("jti").is_some())
        );
        assert!(matches!(
            verify_assertion(&claims, &profile),
            Err(TokenVerificationError::MalformedClaims(_))
        ));

        assert!(claims.as_object_mut().is_some_and(|object| {
            object
                .insert("jti".to_string(), serde_json::json!([]))
                .is_none()
        }));
        assert!(matches!(
            verify_assertion(&claims, &profile),
            Err(TokenVerificationError::MalformedClaims(_))
        ));

        assert!(claims.as_object_mut().is_some_and(|object| {
            object.insert("jti".to_string(), "assertion-1".into());
            object.remove("iat").is_some()
        }));
        assert!(matches!(
            verify_assertion(&claims, &profile),
            Err(TokenVerificationError::Malformed(_))
                | Err(TokenVerificationError::MalformedClaims(_))
        ));
    }

    #[test]
    fn subject_token_profile_enforces_maximum_lifetime_and_age() {
        let profile = SubjectTokenValidationProfile::external_assertion(
            &["https://issuer.example".to_string()],
            "https://keystone.example/v4/oauth2/token",
        );
        let now = chrono::Utc::now().timestamp();

        let mut long_lived = assertion_claims(now);
        long_lived["exp"] = (now + 301).into();
        assert!(matches!(
            verify_assertion(&long_lived, &profile),
            Err(TokenVerificationError::TokenLifetimeTooLong { .. })
        ));

        let mut old = assertion_claims(now - 301);
        old["exp"] = (now - 1).into();
        assert!(matches!(
            verify_assertion(&old, &profile),
            Err(TokenVerificationError::TokenTooOld { .. })
        ));

        let mut future = assertion_claims(now);
        future["iat"] = (now + 120).into();
        assert!(matches!(
            verify_assertion(&future, &profile),
            Err(TokenVerificationError::IssuedInFuture)
        ));
    }

    #[test]
    fn subject_token_profile_rejects_empty_issuer_allowlist() {
        let profile = SubjectTokenValidationProfile::external_assertion(
            &[],
            "https://keystone.example/v4/oauth2/token",
        );
        let claims = assertion_claims(chrono::Utc::now().timestamp());

        assert!(matches!(
            verify_assertion(&claims, &profile),
            Err(TokenVerificationError::InvalidProfile)
        ));
    }

    #[test]
    fn subject_token_profile_requires_exp_issuer_and_audience() {
        let profile = SubjectTokenValidationProfile::external_assertion(
            &["https://issuer.example".to_string()],
            "https://keystone.example/v4/oauth2/token",
        );
        let claims = assertion_claims(chrono::Utc::now().timestamp());
        let (token, jwks, _) = sign(&claims);

        for missing_claim in ["exp", "iss", "aud"] {
            let mut invalid_profile = profile.clone();
            invalid_profile
                .required_claims
                .retain(|claim| claim != missing_claim);
            assert!(matches!(
                verify_subject_token_jwt::<serde_json::Value>(&token, &jwks, &invalid_profile,),
                Err(TokenVerificationError::InvalidProfile)
            ));
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
    fn test_u128_claim_preserved_by_shared_verifier() {
        let now = chrono::Utc::now().timestamp();
        let mut claims = valid_claims(now);
        claims.keystone_ruleset_version = u128::MAX;
        let (token, jwks, _kid) = sign(&claims);
        let result = verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            None,
            &HashSet::new(),
        );
        assert!(matches!(
            result,
            Ok(verified) if verified.keystone_ruleset_version == u128::MAX
        ));
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
        assert!(matches!(err, TokenVerificationError::InvalidAudience));
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
    fn test_id_token_audience_rejected() {
        // ID tokens target the OAuth2 client, not OpenStack resource servers.
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
        assert!(matches!(err, TokenVerificationError::InvalidAudience));
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

    #[test]
    fn test_service_grant_token_with_act_verifies() {
        let now = chrono::Utc::now().timestamp();
        let mut claims = valid_claims(now);
        claims.delegation_context = DelegationContext::ServiceGrant {
            project_id: "project-1".to_string(),
            grant_id: "grant-1".to_string(),
        };
        claims.act = Some(ActClaim {
            client_id: "service-1".to_string(),
            sub_type: ActSubType::Spiffe,
            sub: "spiffe://example/service-1".to_string(),
        });
        let (token, jwks, _kid) = sign(&claims);
        let result = verify_openstack_access_token(
            &token,
            &jwks,
            SigningAlgorithm::Es256,
            &[ISSUER.to_string()],
            None,
            &HashSet::new(),
        );

        assert!(matches!(
            result,
            Ok(verified) if verified.act == claims.act
        ));
    }

    #[test]
    fn test_service_grant_scope_drift_tripwire_trips() {
        let now = chrono::Utc::now().timestamp();
        let mut claims = valid_claims(now);
        claims.delegation_context = DelegationContext::ServiceGrant {
            project_id: "project-1".to_string(),
            grant_id: "grant-1".to_string(),
        };
        claims.act = Some(ActClaim {
            client_id: "service-1".to_string(),
            sub_type: ActSubType::Spiffe,
            sub: "spiffe://example/service-1".to_string(),
        });
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
            Err(TokenVerificationError::InvalidAudience)
        ));
        // Not even a service whose type happens to equal the domain id.
        assert!(matches!(
            verify_for(&claims, Some("compute")),
            Err(TokenVerificationError::InvalidAudience)
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
            Err(TokenVerificationError::InvalidAudience)
        ));
        // A service that does not know its type accepts only the
        // un-narrowed form.
        assert!(matches!(
            verify_for(&claims, None),
            Err(TokenVerificationError::InvalidAudience)
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
