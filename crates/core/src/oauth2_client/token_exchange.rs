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
//! # RFC 8693 Token Exchange (ADR 0026 §12, "v2 Shape", implemented here as
//! the follow-up amendment the ADR itself defers to)
//!
//! Trades an existing Keystone-native delegated credential (trust or
//! application credential; EC2 is deferred, see
//! [`TokenExchangeError::UnsupportedDelegation`]) for a native
//! `OpenStackAccessTokenClaims` access token whose `delegation_context`
//! reflects the presented credential's own delegation, per security.md I2
//! (the delegation boundary is the credential's own immutable project, not
//! the request's current scope).
use openstack_keystone_core_types::auth::{AuthenticationContext, IdentityInfo, ScopeInfo};
use openstack_keystone_core_types::oauth2_client::{
    DelegationContext, OAuth2ClientResource, OpenStackAccessTokenClaims, OpenStackContext,
    OpenStackScope,
};
use openstack_keystone_core_types::token::TokenProviderError;
use thiserror::Error;

use crate::auth::{ExecutionContext, ValidatedSecurityContext};
use crate::keystone::ServiceState;

/// Failure modes for the Token Exchange grant.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TokenExchangeError {
    /// `subject_token` failed the same validation every other endpoint
    /// applies to a bearer token: invalid, expired, or revoked.
    #[error("subject_token failed validation: {0}")]
    InvalidSubjectToken(#[from] TokenProviderError),

    /// `subject_token`'s authentication chain carries no delegation
    /// (security.md I1: the chain, not the scope, is the source of truth).
    /// A plain password/token/mapped/etc. login has nothing to exchange --
    /// this grant exists to re-express an *existing* delegation as a JWT,
    /// not to mint a new one.
    #[error("subject_token carries no delegation to exchange (auth_method `{0}`)")]
    NotDelegated(String),

    /// The delegation kind is recognized but not yet supported by this
    /// grant. Only `Trust` and `AppCred` are implemented; EC2 delegation
    /// exchange is deferred (see the ADR 0026 §12 amendment for why: unlike
    /// a trust/app-cred, whose immutable project lives on the credential
    /// object itself, an EC2 credential's bound project is not currently
    /// reachable from `AuthenticationContext::Ec2Credential` alone, and
    /// guessing wrong on I2's boundary is not an acceptable risk here).
    #[error("token exchange for `{0}` delegation is not yet supported")]
    UnsupportedDelegation(&'static str),

    /// The delegation object (trust/app-cred) has no bound project -- an
    /// unscoped trust, for example. Exchange requires a concrete I2
    /// boundary to enforce; there is nothing to bind the new token to.
    #[error("the presented delegation has no bound project to exchange into a token")]
    NoDelegationProject,

    /// The validated context did not resolve to a real user identity (a
    /// workload `Principal`, not a human `User`). Trusts and application
    /// credentials are always held by real Keystone users, never by
    /// external ingress principals, so this should never happen given a
    /// genuinely trust/app-cred-delegated `subject_token` -- checked rather
    /// than assumed since this builds a signed token.
    #[error("subject_token's principal is not a Keystone user")]
    NotAUserPrincipal,

    /// The validated context carries no resolved authorization/scope.
    #[error("subject_token's context has no resolved authorization scope")]
    NoAuthorization,
}

/// Derive the [`DelegationContext`] an authentication chain carries
/// (security.md I1: keyed on the chain, never on the token's current
/// scope). Pure and side-effect-free so it's unit-testable without a full
/// [`ServiceState`]/[`TokenApi`] round trip.
fn derive_delegation_context(
    ctx: &AuthenticationContext,
) -> Result<DelegationContext, TokenExchangeError> {
    match ctx {
        AuthenticationContext::Trust { trust, .. } => Ok(DelegationContext::Trust {
            project_id: trust
                .project_id
                .clone()
                .ok_or(TokenExchangeError::NoDelegationProject)?,
        }),
        AuthenticationContext::ApplicationCredential {
            application_credential,
            ..
        } => Ok(DelegationContext::AppCred {
            project_id: application_credential.project_id.clone(),
        }),
        AuthenticationContext::Ec2Credential => {
            Err(TokenExchangeError::UnsupportedDelegation("ec2"))
        }
        other => Err(TokenExchangeError::NotDelegated(
            other.auth_type().into_owned(),
        )),
    }
}

/// Validate `subject_token` via the same pipeline every bearer token goes
/// through ([`TokenApi::validate_to_context`]), then derive the
/// [`DelegationContext`] its authentication chain carries.
pub async fn validate_subject_token(
    state: &ServiceState,
    subject_token: &str,
) -> Result<(ValidatedSecurityContext, DelegationContext), TokenExchangeError> {
    let exec = ExecutionContext::internal(state);
    let vsc = state
        .provider
        .get_token_provider()
        .validate_to_context(&exec, subject_token, Some(false), None)
        .await?;

    let delegation_context = derive_delegation_context(vsc.inner().authentication_context())?;

    Ok((vsc, delegation_context))
}

/// Build the [`OpenStackAccessTokenClaims`] for a Token Exchange grant, from
/// the validated `subject_token` context and its derived
/// [`DelegationContext`].
///
/// # Errors
/// See [`TokenExchangeError`] for each rejection reason.
#[allow(clippy::too_many_arguments)]
pub fn build_token_exchange_claims(
    client: &OAuth2ClientResource,
    vsc: &ValidatedSecurityContext,
    delegation_context: DelegationContext,
    issuer: &str,
    jti: String,
    iat: i64,
    exp: i64,
) -> Result<OpenStackAccessTokenClaims, TokenExchangeError> {
    let principal = vsc.inner().principal();
    let (user_id, user_name, user_domain_id) = match &principal.identity {
        IdentityInfo::User(u) => (
            u.user_id.clone(),
            u.user
                .as_ref()
                .map(|r| r.name.clone())
                .unwrap_or_else(|| u.user_id.clone()),
            u.user_domain.as_ref().map(|d| d.id.clone()),
        ),
        IdentityInfo::Principal(_) => return Err(TokenExchangeError::NotAUserPrincipal),
    };

    let authz = vsc
        .inner()
        .authorization()
        .ok_or(TokenExchangeError::NoAuthorization)?;
    let role_refs = authz.effective_roles().unwrap_or(&[]).to_vec();
    let role_names: Vec<String> = role_refs.iter().filter_map(|r| r.name.clone()).collect();

    let scope = match &authz.scope {
        ScopeInfo::Project {
            project,
            project_domain,
        } => OpenStackScope::Project {
            project_id: project.id.clone(),
            project_domain_id: project_domain.id.clone(),
            roles: role_refs,
        },
        ScopeInfo::Domain(domain) => OpenStackScope::Domain {
            domain_id: domain.id.clone(),
            roles: role_refs,
        },
        ScopeInfo::System(system_id) => OpenStackScope::System {
            system_id: system_id.clone(),
            roles: role_refs,
        },
        _ => OpenStackScope::Unscoped,
    };

    let amr: Vec<String> = vsc
        .inner()
        .authentication_context()
        .methods()
        .into_iter()
        .collect();

    Ok(OpenStackAccessTokenClaims {
        iss: issuer.to_string(),
        sub: user_id.clone(),
        aud: format!("openstack-apis:{}", client.domain_id),
        client_id: client.client_id.clone(),
        exp,
        iat,
        nbf: iat,
        jti,
        // No `MappingRuleSet` is involved in a token-exchange grant (the
        // subject is an already-authenticated native Keystone credential,
        // not an external ingress source) so there is no ruleset state to
        // anchor to. `0` is a sentinel meaning "not mapping-engine-derived"
        // -- the claim is documented as advisory-only (ADR 0026 §11) and
        // gates nothing downstream.
        keystone_ruleset_version: 0,
        amr,
        token_use: "access".to_string(),
        delegation_context,
        openstack_context: OpenStackContext {
            user_id,
            user_name,
            user_domain_id,
            scope,
            roles: role_names,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_core_types::auth::{
        AuthzInfoBuilder, PrincipalIdentityInfoBuilder, PrincipalInfo, SecurityContext,
        UserIdentityInfoBuilder,
    };
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use openstack_keystone_core_types::resource::{Domain, Project};
    use openstack_keystone_core_types::trust::Trust;

    fn trust_context(project_id: Option<&str>) -> AuthenticationContext {
        AuthenticationContext::Trust {
            trust: Trust {
                id: "trust-1".to_string(),
                impersonation: false,
                project_id: project_id.map(str::to_string),
                trustor_user_id: "trustor-1".to_string(),
                trustee_user_id: "trustee-1".to_string(),
                ..Default::default()
            },
            token: None,
        }
    }

    fn app_cred_context(project_id: &str) -> AuthenticationContext {
        AuthenticationContext::ApplicationCredential {
            application_credential:
                openstack_keystone_core_types::application_credential::ApplicationCredential {
                    access_rules: None,
                    description: None,
                    expires_at: None,
                    id: "appcred-1".to_string(),
                    name: "appcred".to_string(),
                    project_id: project_id.to_string(),
                    roles: vec![],
                    unrestricted: false,
                    user_id: "user-1".to_string(),
                },
            token: None,
        }
    }

    #[test]
    fn test_derive_delegation_context_trust() {
        let ctx = trust_context(Some("project-1"));
        let result = derive_delegation_context(&ctx).unwrap();
        assert_eq!(
            result,
            DelegationContext::Trust {
                project_id: "project-1".to_string()
            }
        );
    }

    #[test]
    fn test_derive_delegation_context_trust_without_project_is_rejected() {
        let ctx = trust_context(None);
        let err = derive_delegation_context(&ctx).unwrap_err();
        assert!(matches!(err, TokenExchangeError::NoDelegationProject));
    }

    #[test]
    fn test_derive_delegation_context_app_cred() {
        let ctx = app_cred_context("project-2");
        let result = derive_delegation_context(&ctx).unwrap();
        assert_eq!(
            result,
            DelegationContext::AppCred {
                project_id: "project-2".to_string()
            }
        );
    }

    #[test]
    fn test_derive_delegation_context_ec2_is_unsupported() {
        let err = derive_delegation_context(&AuthenticationContext::Ec2Credential).unwrap_err();
        assert!(matches!(
            err,
            TokenExchangeError::UnsupportedDelegation("ec2")
        ));
    }

    #[test]
    fn test_derive_delegation_context_plain_password_is_rejected() {
        let err = derive_delegation_context(&AuthenticationContext::Password).unwrap_err();
        assert!(matches!(err, TokenExchangeError::NotDelegated(_)));
    }

    fn sample_client() -> OAuth2ClientResource {
        OAuth2ClientResource {
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: "domain-1".into(),
            client_secret_hash: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: "client_secret_basic".into(),
            grant_types: vec![],
            require_pkce: false,
            allowed_scopes: vec![],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    fn user_vsc(authentication_context: AuthenticationContext) -> ValidatedSecurityContext {
        let user = UserResponseBuilder::default()
            .id("user-1")
            .domain_id("domain-1")
            .enabled(true)
            .name("trustor")
            .build()
            .unwrap();
        let authz = AuthzInfoBuilder::default()
            .roles(vec![])
            .scope(ScopeInfo::Project {
                project: Project {
                    id: "project-1".to_string(),
                    domain_id: "domain-1".to_string(),
                    enabled: true,
                    name: "project".to_string(),
                    ..Default::default()
                },
                project_domain: Domain {
                    id: "domain-1".to_string(),
                    name: "domain".to_string(),
                    enabled: true,
                    ..Default::default()
                },
            })
            .build()
            .unwrap();
        let sc = SecurityContext::test_build()
            .authentication_context(authentication_context)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("user-1")
                        .user(user)
                        .user_domain(Domain {
                            id: "domain-1".to_string(),
                            name: "domain".to_string(),
                            enabled: true,
                            ..Default::default()
                        })
                        .build()
                        .unwrap(),
                ),
            })
            .authorization(authz)
            .build();
        ValidatedSecurityContext::test_new(sc)
    }

    #[test]
    fn test_build_token_exchange_claims_for_trust() {
        let vsc = user_vsc(trust_context(Some("project-1")));
        let claims = build_token_exchange_claims(
            &sample_client(),
            &vsc,
            DelegationContext::Trust {
                project_id: "project-1".to_string(),
            },
            "https://ks.example/v4/oauth2/domain-1",
            "jti-1".to_string(),
            1000,
            1900,
        )
        .unwrap();

        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.aud, "openstack-apis:domain-1");
        assert!(claims.amr.contains(&"trust".to_string()));
        assert_eq!(
            claims.delegation_context,
            DelegationContext::Trust {
                project_id: "project-1".to_string()
            }
        );
    }

    #[test]
    fn test_build_token_exchange_claims_rejects_non_user_principal() {
        let sc = SecurityContext::test_build()
            .authentication_context(trust_context(Some("project-1")))
            .principal(PrincipalInfo {
                identity: IdentityInfo::Principal(
                    PrincipalIdentityInfoBuilder::default()
                        .id("workload-1")
                        .issuer("spiffe://example")
                        .build()
                        .unwrap(),
                ),
            })
            .authorization(
                AuthzInfoBuilder::default()
                    .roles(vec![])
                    .scope(ScopeInfo::Unscoped)
                    .build()
                    .unwrap(),
            )
            .build();
        let vsc = ValidatedSecurityContext::test_new(sc);

        let err = build_token_exchange_claims(
            &sample_client(),
            &vsc,
            DelegationContext::Trust {
                project_id: "project-1".to_string(),
            },
            "https://ks.example/v4/oauth2/domain-1",
            "jti-1".to_string(),
            1000,
            1900,
        )
        .unwrap_err();
        assert!(matches!(err, TokenExchangeError::NotAUserPrincipal));
    }
}
