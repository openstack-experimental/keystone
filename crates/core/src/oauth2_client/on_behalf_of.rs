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
//! On-behalf-of exchange (ADR 0036 §6).
//!
//! A delegatable service trades the token a user handed it for a token of
//! its own that names the user as `sub` and the service as `act`. The chain
//! is bound to the user's original token (`root_jti`) and to the time the
//! user authenticated (`auth_time`): revoking the token, disabling the user
//! or losing the roles ends the chain at the next hop, and no chain outlives
//! the client's `max_operation_lifetime`.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, TimeZone, Utc};
use thiserror::Error;
use tracing::warn;

use openstack_keystone_core_types::auth::*;
use openstack_keystone_core_types::oauth2_client::{
    ActClaim, ActSubType, Audience, DelegationContext, OAuth2ClientResource,
    OpenStackAccessTokenClaims, OpenStackContext, OpenStackScope, spiffe_id_matches_any,
};
use openstack_keystone_key_repository::asymmetric::SigningAlgorithm;

use crate::auth::{ExecutionContext, ValidatedSecurityContext};
use crate::common::SpiffeId;
use crate::keystone::ServiceState;
use crate::oauth2_client::service::TLS_CLIENT_AUTH;
use crate::oauth2_client::verify::verify_openstack_subject_token;

/// The `amr` entry every on-behalf-of token carries.
const ON_BEHALF_OF: &str = "on_behalf_of";

/// Why an exchange was refused. Each maps to one token endpoint error.
#[derive(Debug, Error)]
pub enum OnBehalfOfError {
    /// The presented SVID does not authenticate the client, or the client
    /// may not exchange on behalf of users (`invalid_client`).
    #[error("the client is not authenticated for on-behalf-of exchange")]
    InvalidClient,
    /// The subject token is invalid, expired or revoked (`invalid_grant`).
    #[error("the subject token is not valid")]
    InvalidSubject,
    /// The subject's authentication cannot be exchanged: a trust, a service
    /// grant, a token of another actor or a restricted token
    /// (`invalid_grant`).
    #[error("the subject token's authentication cannot be exchanged: {0}")]
    UnsupportedSubject(String),
    /// The subject's scope is outside the domain of this endpoint, or the
    /// client lacks the `cross_domain` opt-in (`invalid_grant`).
    #[error("the subject token is not exchangeable at this endpoint")]
    CrossDomain,
    /// The chain is older than the client's `max_operation_lifetime`
    /// (`invalid_grant`).
    #[error("the operation lifetime of the client is exhausted")]
    OperationExpired,
    /// The user, a domain or the project is not usable, or the user holds no
    /// role left (`invalid_grant`).
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    /// A storage or provider failure (`server_error`).
    #[error("{0}")]
    Provider(String),
}

impl OnBehalfOfError {
    fn provider(e: impl std::fmt::Display) -> Self {
        Self::Provider(e.to_string())
    }
}

/// The token the user (or an earlier hop) handed to the service.
#[derive(Clone, Copy, Debug)]
pub enum OnBehalfOfSubject<'a> {
    /// A Keystone token (`urn:openstack:params:oauth:token-type:keystone`).
    Keystone(&'a str),
    /// A token this endpoint minted for the same client in an earlier hop
    /// (`urn:ietf:params:oauth:token-type:access_token`).
    Hop(&'a str),
}

/// What identifies a request to [`exchange_on_behalf_of`].
#[derive(Debug)]
pub struct OnBehalfOfRequest<'a> {
    /// The domain of the token endpoint, which signs the result.
    pub domain_id: &'a str,
    /// The issuer of the endpoint, to recognise its own hop tokens.
    pub issuer: &'a str,
    /// The configured `[oauth2] signing_algorithm`.
    pub signing_algorithm: SigningAlgorithm,
    /// The X.509-SVID of the TLS connection.
    pub svid: &'a SpiffeId,
    /// The `client_id` of the request. Required: an SVID alone does not
    /// name the client.
    pub client_id: &'a str,
    /// The token to exchange.
    pub subject: OnBehalfOfSubject<'a>,
}

/// A successful exchange: the user's security context bounded by the
/// chain, and the authenticated client.
#[derive(Debug)]
pub struct ExchangedOnBehalfOf {
    /// The user acting through the service, scoped like the subject.
    pub vsc: ValidatedSecurityContext,
    /// The client holding the exchanged token.
    pub client: OAuth2ClientResource,
    /// When the chain ends: `auth_time` plus the client's
    /// `max_operation_lifetime`. Tokens must not outlive it.
    pub valid_until: DateTime<Utc>,
    /// The audience of the hop token that was exchanged, `None` for a
    /// user's Keystone token. A renewed token must not widen it.
    pub subject_audience: Option<Audience>,
}

/// The facts of the subject's own authentication the chain keeps.
struct Subject {
    user_id: String,
    scope: ScopeInfo,
    delegated_project_id: Option<String>,
    delegated_role_ids: Option<Vec<String>>,
    application_credential_id: Option<String>,
    methods: BTreeSet<String>,
    auth_time: DateTime<Utc>,
    root_jti: String,
    audience: Option<Audience>,
}

/// Exchange the subject token of `request` for a user security context
/// bound to the authenticated client (ADR 0036 §6.2, §6.3).
///
/// A user token starts a chain; a hop token of the same client continues
/// it. Either way the revocation of the chain's root token, the user and
/// domain state and the live roles are checked again.
pub async fn exchange_on_behalf_of(
    state: &ServiceState,
    request: &OnBehalfOfRequest<'_>,
) -> Result<ExchangedOnBehalfOf, OnBehalfOfError> {
    let internal = ExecutionContext::internal(state);
    let client = authenticate_client(state, request).await?;
    // `authenticate_client` returned a client with this policy.
    let max_operation_lifetime = client
        .on_behalf_of_policy()
        .and_then(|policy| policy.max_operation_lifetime)
        .ok_or(OnBehalfOfError::InvalidClient)?;

    let subject = match request.subject {
        OnBehalfOfSubject::Keystone(token) => keystone_subject(state, token).await?,
        OnBehalfOfSubject::Hop(token) => hop_subject(state, request, &client, token).await?,
    };

    // §6.3: no chain outlives the client's operation lifetime.
    let lifetime = Duration::try_seconds(i64::try_from(max_operation_lifetime).unwrap_or(i64::MAX))
        .unwrap_or(Duration::MAX);
    let valid_until = subject
        .auth_time
        .checked_add_signed(lifetime)
        .unwrap_or(DateTime::<Utc>::MAX_UTC);
    if Utc::now() >= valid_until {
        return Err(OnBehalfOfError::OperationExpired);
    }

    // The issuing domain must own the scope, and a client or user of
    // another domain needs the `cross_domain` opt-in.
    let scope_domain_id = match &subject.scope {
        ScopeInfo::Project { project_domain, .. } => project_domain.id.as_str(),
        ScopeInfo::Domain(domain) => domain.id.as_str(),
        _ => {
            return Err(OnBehalfOfError::UnsupportedSubject(
                "only project and domain scopes are exchangeable".into(),
            ));
        }
    };
    if scope_domain_id != request.domain_id {
        return Err(OnBehalfOfError::CrossDomain);
    }
    let user = state
        .provider
        .get_identity_provider()
        .get_user(&internal, &subject.user_id)
        .await
        .map_err(OnBehalfOfError::provider)?
        .ok_or(AuthenticationError::Unauthorized)?;
    let cross_domain = client
        .on_behalf_of_policy()
        .is_some_and(|policy| policy.cross_domain);
    if (client.domain_id != request.domain_id || client.domain_id != user.domain_id)
        && !cross_domain
    {
        return Err(OnBehalfOfError::CrossDomain);
    }

    let auth_result = AuthenticationResultBuilder::default()
        .audit_id(subject.root_jti.clone())
        .context(AuthenticationContext::OnBehalfOf {
            actor: ActorInfo {
                client_id: client.client_id.clone(),
                spiffe_id: request.svid.to_string(),
            },
            delegated_project_id: subject.delegated_project_id,
            delegated_role_ids: subject.delegated_role_ids,
            application_credential_id: subject.application_credential_id,
            subject_methods: subject.methods,
            auth_time: subject.auth_time,
            root_jti: subject.root_jti,
        })
        .principal(
            PrincipalInfoBuilder::default()
                .identity(IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id(subject.user_id)
                        .user(user)
                        .build()
                        .map_err(AuthenticationError::from)?,
                ))
                .build()
                .map_err(AuthenticationError::from)?,
        )
        .build()
        .map_err(AuthenticationError::from)?;
    let ctx = SecurityContext::try_from(auth_result)?;
    // Live user, domain and role checks as on the first hop.
    let vsc = ValidatedSecurityContext::new_for_scope(ctx, subject.scope, state).await?;

    // §6.3 check 1: the root token is not revoked.
    if state
        .provider
        .get_revoke_provider()
        .is_token_revoked(&internal, &vsc)
        .await
        .map_err(OnBehalfOfError::provider)?
    {
        return Err(OnBehalfOfError::InvalidSubject);
    }

    Ok(ExchangedOnBehalfOf {
        vsc,
        client,
        valid_until,
        subject_audience: subject.audience,
    })
}

/// Resolve the client of the request and authenticate it by its SVID.
async fn authenticate_client(
    state: &ServiceState,
    request: &OnBehalfOfRequest<'_>,
) -> Result<OAuth2ClientResource, OnBehalfOfError> {
    let client = state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&ExecutionContext::internal(state), request.client_id)
        .await
        .map_err(OnBehalfOfError::provider)?
        .ok_or(OnBehalfOfError::InvalidClient)?;
    if client.on_behalf_of_policy().is_none()
        || client.token_endpoint_auth_method != TLS_CLIENT_AUTH
        || !spiffe_id_matches_any(&client.spiffe_ids, request.svid.as_str())
    {
        return Err(OnBehalfOfError::InvalidClient);
    }
    Ok(client)
}

/// Start a chain from a Keystone token (§6.2 checks 1 and 2).
async fn keystone_subject(state: &ServiceState, token: &str) -> Result<Subject, OnBehalfOfError> {
    let vsc = state
        .provider
        .get_token_provider()
        .validate_to_context(&ExecutionContext::internal(state), token, Some(false), None)
        .await
        .map_err(|e| {
            warn!(error = %e, "on-behalf-of subject token rejected");
            OnBehalfOfError::InvalidSubject
        })?;
    let sc = vsc.inner();
    let IdentityInfo::User(user) = &sc.principal().identity else {
        return Err(OnBehalfOfError::UnsupportedSubject(
            "the subject is not a user".into(),
        ));
    };
    // No re-delegation: only a plain chain or an application credential can
    // be exchanged, and a restriction cannot be carried along.
    let (delegated_project_id, delegated_role_ids, application_credential_id) = match sc
        .authentication_context()
    {
        // A restricted credential (`unrestricted == false`) must not mint
        // the credentials and trusts it is forbidden to, and the chain
        // cannot carry that restriction along.
        AuthenticationContext::ApplicationCredential {
            application_credential,
            ..
        } if !application_credential.unrestricted => {
            return Err(OnBehalfOfError::UnsupportedSubject(
                "restricted application credential".into(),
            ));
        }
        AuthenticationContext::ApplicationCredential {
            application_credential,
            ..
        } => (
            Some(application_credential.project_id.clone()),
            Some(
                application_credential
                    .roles
                    .iter()
                    .map(|r| r.id.clone())
                    .collect(),
            ),
            Some(application_credential.id.clone()),
        ),
        other if other.is_delegated() => {
            return Err(OnBehalfOfError::UnsupportedSubject(
                other.auth_type().into_owned(),
            ));
        }
        AuthenticationContext::ServiceClient { .. } | AuthenticationContext::OnBehalfOf { .. } => {
            return Err(OnBehalfOfError::UnsupportedSubject(
                sc.authentication_context().auth_type().into_owned(),
            ));
        }
        _ => (None, None, None),
    };
    if sc.token_restriction().is_some() {
        return Err(OnBehalfOfError::UnsupportedSubject(
            "restricted token".into(),
        ));
    }
    let fernet = vsc.token().map_err(|_| OnBehalfOfError::InvalidSubject)?;
    // The first audit id is the key revocation events of this token are
    // recorded under (`RevocationEventListParametersBuilder`), so revoking
    // the token the user handed over ends the chain.
    let root_jti = fernet
        .audit_ids()
        .first()
        .cloned()
        .ok_or(OnBehalfOfError::InvalidSubject)?;
    // A rescoped token carries a fresh `issued_at` but inherits the expiry
    // of its parent, so the user's authentication time is no later than
    // the expiry less the token lifetime. Using it keeps rescoping from
    // moving `auth_time` (and with it the chain's end) forward.
    let token_lifetime = Duration::try_seconds(
        i64::try_from(state.config_manager.config.read().await.token.expiration)
            .unwrap_or(i64::MAX),
    )
    .unwrap_or(Duration::MAX);
    let auth_time = fernet
        .expires_at()
        .checked_sub_signed(token_lifetime)
        .map_or(*fernet.issued_at(), |t| t.min(*fernet.issued_at()));
    let scope = sc
        .authorization()
        .ok_or(OnBehalfOfError::InvalidSubject)?
        .scope
        .clone();
    Ok(Subject {
        user_id: user.user_id.clone(),
        scope,
        delegated_project_id,
        delegated_role_ids,
        application_credential_id,
        methods: sc.authentication_context().methods().into_iter().collect(),
        auth_time,
        root_jti,
        audience: None,
    })
}

/// Continue a chain from a hop token this endpoint minted for the same
/// client (§6.3).
async fn hop_subject(
    state: &ServiceState,
    request: &OnBehalfOfRequest<'_>,
    client: &OAuth2ClientResource,
    token: &str,
) -> Result<Subject, OnBehalfOfError> {
    let keys = state.provider.get_oauth2_key_provider();
    let jwks = keys
        .jwks(state, request.domain_id)
        .await
        .map_err(|_| OnBehalfOfError::InvalidSubject)?;
    let revoked_jtis = keys
        .revoked_jtis(state, request.domain_id)
        .await
        .map_err(OnBehalfOfError::provider)?;
    let claims = verify_openstack_subject_token(
        token,
        &jwks,
        request.signing_algorithm,
        &[request.issuer.to_string()],
        &revoked_jtis,
    )
    .map_err(|e| {
        warn!(error = %e, "on-behalf-of hop token rejected");
        OnBehalfOfError::InvalidSubject
    })?;

    // The chain belongs to one client: a hop token of another actor is a
    // re-delegation.
    let DelegationContext::OnBehalfOf {
        actor_client_id,
        auth_time,
        root_jti,
        project_id,
        delegated_role_ids,
        application_credential_id,
    } = claims.delegation_context
    else {
        return Err(OnBehalfOfError::UnsupportedSubject(
            "not an on-behalf-of token".into(),
        ));
    };
    if actor_client_id != client.client_id {
        return Err(OnBehalfOfError::UnsupportedSubject(
            "on-behalf-of token of another actor".into(),
        ));
    }
    let auth_time = Utc
        .timestamp_opt(auth_time, 0)
        .single()
        .ok_or(OnBehalfOfError::InvalidSubject)?;

    let internal = ExecutionContext::internal(state);
    // The chain ends with the application credential it was started from.
    if let Some(id) = &application_credential_id {
        let credential = state
            .provider
            .get_application_credential_provider()
            .get_application_credential(&internal, id)
            .await
            .map_err(OnBehalfOfError::provider)?
            .ok_or(OnBehalfOfError::InvalidSubject)?;
        if credential.user_id != claims.sub {
            return Err(OnBehalfOfError::InvalidSubject);
        }
        if credential.expires_at.is_some_and(|t| t < Utc::now()) {
            return Err(AuthenticationError::AuthApplicationCredentialExpired.into());
        }
    }
    let resource = state.provider.get_resource_provider();
    let scope = match claims.openstack_context.scope {
        OpenStackScope::Project {
            project_id: scope_project_id,
            ..
        } => {
            let project = resource
                .get_project(&internal, &scope_project_id)
                .await
                .map_err(OnBehalfOfError::provider)?
                .filter(|p| p.enabled)
                .ok_or(AuthenticationError::ProjectDisabled(scope_project_id))?;
            let project_domain = resource
                .get_domain(&internal, &project.domain_id)
                .await
                .map_err(OnBehalfOfError::provider)?
                .filter(|d| d.enabled)
                .ok_or_else(|| AuthenticationError::DomainDisabled(project.domain_id.clone()))?;
            ScopeInfo::Project {
                project,
                project_domain,
            }
        }
        OpenStackScope::Domain { domain_id, .. } => ScopeInfo::Domain(
            resource
                .get_domain(&internal, &domain_id)
                .await
                .map_err(OnBehalfOfError::provider)?
                .filter(|d| d.enabled)
                .ok_or(AuthenticationError::DomainDisabled(domain_id))?,
        ),
        _ => {
            return Err(OnBehalfOfError::UnsupportedSubject(
                "only project and domain scopes are exchangeable".into(),
            ));
        }
    };

    Ok(Subject {
        user_id: claims.sub,
        scope,
        delegated_project_id: project_id,
        delegated_role_ids,
        application_credential_id,
        audience: Some(claims.aud),
        methods: claims
            .amr
            .into_iter()
            .filter(|m| m != ON_BEHALF_OF)
            .collect(),
        auth_time,
        root_jti,
    })
}

/// Build the access token claims of an exchanged chain (ADR 0036 §6.2):
/// `sub` is the user, `act` the service, `amr` the union of the subject's
/// methods and `on_behalf_of`, and the delegation context carries the
/// chain's facts unchanged from hop to hop. No refresh token exists; the
/// service exchanges again.
///
/// # Errors
/// [`OnBehalfOfError`] when the context is not an on-behalf-of one or is not
/// fully resolved.
#[allow(clippy::too_many_arguments)]
pub fn build_on_behalf_of_claims(
    exchanged: &ExchangedOnBehalfOf,
    issuer: &str,
    jti: String,
    iat: i64,
    exp: i64,
    aud: Audience,
) -> Result<OpenStackAccessTokenClaims, OnBehalfOfError> {
    let sc = exchanged.vsc.inner();
    let AuthenticationContext::OnBehalfOf {
        actor,
        delegated_project_id,
        delegated_role_ids,
        application_credential_id,
        auth_time,
        root_jti,
        ..
    } = sc.authentication_context()
    else {
        return Err(OnBehalfOfError::InvalidSubject);
    };
    let IdentityInfo::User(user) = &sc.principal().identity else {
        return Err(AuthenticationError::AuthzPrincipalMismatch.into());
    };
    let authz = sc
        .authorization()
        .ok_or(AuthenticationError::SecurityContextNotResolved)?;
    let roles = authz.effective_roles().unwrap_or(&[]).to_vec();
    let role_names: Vec<String> = roles.iter().filter_map(|r| r.name.clone()).collect();
    let scope = match &authz.scope {
        ScopeInfo::Project {
            project,
            project_domain,
        } => OpenStackScope::Project {
            project_id: project.id.clone(),
            project_domain_id: project_domain.id.clone(),
            roles,
        },
        ScopeInfo::Domain(domain) => OpenStackScope::Domain {
            domain_id: domain.id.clone(),
            roles,
        },
        _ => return Err(AuthenticationError::ScopeNotAllowed.into()),
    };

    Ok(OpenStackAccessTokenClaims {
        iss: issuer.to_string(),
        sub: user.user_id.clone(),
        aud,
        client_id: actor.client_id.clone(),
        exp,
        iat,
        nbf: iat,
        jti,
        // Not mapping-engine-derived; see the token exchange grant.
        keystone_ruleset_version: 0,
        amr: {
            let mut methods: Vec<String> =
                sc.authentication_context().methods().into_iter().collect();
            methods.sort();
            methods
        },
        token_use: "access".to_string(),
        delegation_context: DelegationContext::OnBehalfOf {
            actor_client_id: actor.client_id.clone(),
            auth_time: auth_time.timestamp(),
            root_jti: root_jti.clone(),
            project_id: delegated_project_id.clone(),
            delegated_role_ids: delegated_role_ids.clone(),
            application_credential_id: application_credential_id.clone(),
        },
        act: Some(ActClaim {
            client_id: actor.client_id.clone(),
            sub_type: ActSubType::Spiffe,
            sub: actor.spiffe_id.clone(),
        }),
        openstack_context: OpenStackContext {
            user_id: user.user_id.clone(),
            user_name: user
                .user
                .as_ref()
                .map(|u| u.name.clone())
                .unwrap_or_else(|| user.user_id.clone()),
            user_domain_id: user.user_domain.as_ref().map(|d| d.id.clone()),
            scope,
            roles: role_names,
        },
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use openstack_keystone_core_types::application_credential::ApplicationCredential;
    use openstack_keystone_core_types::assignment::{Assignment, AssignmentType};
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use openstack_keystone_core_types::oauth2_client::DelegationPolicy;
    use openstack_keystone_core_types::resource::{Domain, Project};
    use openstack_keystone_core_types::role::RoleRef;
    use openstack_keystone_core_types::token::{
        FernetToken, TokenProviderError, payload::ProjectScopePayloadBuilder,
    };
    use openstack_keystone_core_types::trust::Trust;

    use super::*;
    use crate::assignment::MockAssignmentProvider;
    use crate::identity::MockIdentityProvider;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::revoke::MockRevokeProvider;
    use crate::role::MockRoleProvider;
    use crate::tests::get_mocked_state;
    use crate::token::MockTokenProvider;

    const SVID: &str = "spiffe://td/service/glance/host/h1";
    const ISSUER: &str = "https://ks/v4/oauth2/d1";

    fn client(policy: Option<DelegationPolicy>, domain_id: &str) -> OAuth2ClientResource {
        OAuth2ClientResource {
            client_id: "glance".into(),
            provider_id: "glance".into(),
            domain_id: domain_id.into(),
            client_secret_hash: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: TLS_CLIENT_AUTH.into(),
            grant_types: vec![],
            require_pkce: false,
            allowed_scopes: vec![],
            pre_authorized: false,
            enabled: true,
            claims_template: HashMap::new(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
            name: "Glance".into(),
            description: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            spiffe_ids: vec!["spiffe://td/service/glance/host/*".into()],
            delegation: policy,
        }
    }

    fn policy(cross_domain: bool) -> Option<DelegationPolicy> {
        Some(DelegationPolicy {
            on_behalf_of: true,
            cross_domain,
            max_operation_lifetime: Some(3600),
            ..Default::default()
        })
    }

    fn user(id: &str) -> openstack_keystone_core_types::identity::UserResponse {
        UserResponseBuilder::default()
            .id(id)
            .domain_id("d1")
            .enabled(true)
            .name("alice")
            .build()
            .unwrap()
    }

    fn token(issued_at: DateTime<Utc>) -> FernetToken {
        token_expiring(issued_at, Utc::now() + Duration::hours(1))
    }

    fn token_expiring(issued_at: DateTime<Utc>, expires_at: DateTime<Utc>) -> FernetToken {
        FernetToken::ProjectScope(
            ProjectScopePayloadBuilder::default()
                .methods(vec!["password".to_string()].into_iter())
                .audit_ids(vec!["audit-1".to_string()].into_iter())
                .user_id("u1")
                .project_id("p1")
                .expires_at(expires_at)
                .issued_at(issued_at)
                .build()
                .unwrap(),
        )
    }

    fn project(domain_id: &str) -> ScopeInfo {
        ScopeInfo::Project {
            project: Project {
                id: "p1".into(),
                domain_id: domain_id.into(),
                enabled: true,
                name: "p".into(),
                ..Default::default()
            },
            project_domain: Domain {
                id: domain_id.into(),
                name: domain_id.into(),
                enabled: true,
                ..Default::default()
            },
        }
    }

    /// What the token provider resolves the user's token to.
    fn subject_vsc(
        context: AuthenticationContext,
        issued_at: DateTime<Utc>,
        scope_domain: &str,
    ) -> ValidatedSecurityContext {
        subject_vsc_with_token(context, token(issued_at), scope_domain)
    }

    fn subject_vsc_with_token(
        context: AuthenticationContext,
        token: FernetToken,
        scope_domain: &str,
    ) -> ValidatedSecurityContext {
        let auth = AuthenticationResultBuilder::default()
            .context(context)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("u1")
                        .user(user("u1"))
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap();
        let mut sc = SecurityContext::try_from(auth).unwrap();
        sc.set_token(token);
        sc.set_authorization(
            AuthzInfoBuilder::default()
                .scope(project(scope_domain))
                .roles(vec![RoleRef {
                    id: "member".into(),
                    name: Some("member".into()),
                    domain_id: None,
                }])
                .build()
                .unwrap(),
        );
        ValidatedSecurityContext::test_new(sc)
    }

    fn app_cred() -> AuthenticationContext {
        AuthenticationContext::ApplicationCredential {
            application_credential: ApplicationCredential {
                access_rules: None,
                description: None,
                expires_at: None,
                id: "ac1".into(),
                name: "ac".into(),
                project_id: "p1".into(),
                roles: vec![RoleRef {
                    id: "member".into(),
                    name: Some("member".into()),
                    domain_id: None,
                }],
                unrestricted: true,
                user_id: "u1".into(),
            },
            token: None,
        }
    }

    fn assignment(role_id: &str) -> Assignment {
        Assignment {
            actor_id: "u1".into(),
            role_id: role_id.into(),
            role_name: Some(role_id.into()),
            target_id: "p1".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: None,
        }
    }

    async fn state(
        subject: Option<ValidatedSecurityContext>,
        client: OAuth2ClientResource,
        revoked: bool,
    ) -> ServiceState {
        let mut tokens = MockTokenProvider::default();
        tokens
            .expect_validate_to_context()
            .returning(move |_, _, _, _| match &subject {
                Some(vsc) => Ok(vsc.clone()),
                None => Err(TokenProviderError::Expired),
            });
        let mut clients = MockOauth2ClientProvider::default();
        clients
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let mut identity = MockIdentityProvider::default();
        identity
            .expect_get_user()
            .returning(|_, id| Ok(Some(user(id))));
        let mut resource = MockResourceProvider::default();
        resource.expect_get_domain().returning(|_, id| {
            Ok(Some(Domain {
                id: id.to_string(),
                name: id.to_string(),
                enabled: true,
                ..Default::default()
            }))
        });
        let mut assignments = MockAssignmentProvider::default();
        assignments
            .expect_list_role_assignments()
            .returning(|_, _| Ok(vec![assignment("member"), assignment("admin")]));
        let mut role = MockRoleProvider::default();
        role.expect_expand_implied_roles().returning(|_, _| Ok(()));
        let mut revoke = MockRevokeProvider::default();
        revoke
            .expect_is_token_revoked()
            .returning(move |_, _| Ok(revoked));
        get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_token(tokens)
                    .mock_oauth2_client(clients)
                    .mock_identity(identity)
                    .mock_resource(resource)
                    .mock_assignment(assignments)
                    .mock_role(role)
                    .mock_revoke(revoke),
            ),
        )
        .await
    }

    fn request<'a>(svid: &'a SpiffeId, subject: OnBehalfOfSubject<'a>) -> OnBehalfOfRequest<'a> {
        OnBehalfOfRequest {
            domain_id: "d1",
            issuer: ISSUER,
            signing_algorithm: SigningAlgorithm::Es256,
            svid,
            client_id: "glance",
            subject,
        }
    }

    fn svid() -> SpiffeId {
        SpiffeId::new(SVID).unwrap()
    }

    async fn exchange(state: &ServiceState) -> Result<ExchangedOnBehalfOf, OnBehalfOfError> {
        exchange_on_behalf_of(state, &request(&svid(), OnBehalfOfSubject::Keystone("t"))).await
    }

    fn claims(exchanged: &ExchangedOnBehalfOf) -> OpenStackAccessTokenClaims {
        build_on_behalf_of_claims(
            exchanged,
            ISSUER,
            "jti".into(),
            1,
            2,
            Audience::control_plane(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_plain_subject_starts_a_chain() {
        let issued_at = Utc::now() - Duration::minutes(5);
        let state = state(
            Some(subject_vsc(
                AuthenticationContext::Token(token(issued_at)),
                issued_at,
                "d1",
            )),
            client(policy(false), "d1"),
            false,
        )
        .await;
        let exchanged = exchange(&state).await.unwrap();
        let claims = claims(&exchanged);
        assert_eq!(claims.sub, "u1");
        assert_eq!(claims.client_id, "glance");
        // The union of the subject's methods and `on_behalf_of`.
        assert_eq!(claims.amr, ["on_behalf_of", "password", "token"]);
        assert_eq!(
            claims.act,
            Some(ActClaim {
                client_id: "glance".into(),
                sub_type: ActSubType::Spiffe,
                sub: SVID.into(),
            })
        );
        // The user's live roles, since a plain subject has no ceiling.
        let mut roles = claims.openstack_context.roles.clone();
        roles.sort();
        roles.dedup();
        assert_eq!(roles, ["admin", "member"]);
        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(json["delegation_context"]["auth_method"], "on_behalf_of");
        assert_eq!(json["delegation_context"]["actor_client_id"], "glance");
        assert_eq!(json["delegation_context"]["root_jti"], "audit-1");
        assert_eq!(
            json["delegation_context"]["auth_time"],
            issued_at.timestamp()
        );
        assert!(json["delegation_context"]["delegated_project_id"].is_null());
        assert_eq!(exchanged.valid_until, issued_at + Duration::seconds(3600));
    }

    #[tokio::test]
    async fn test_application_credential_subject_keeps_its_bound() {
        let issued_at = Utc::now();
        let state = state(
            Some(subject_vsc(app_cred(), issued_at, "d1")),
            client(policy(false), "d1"),
            false,
        )
        .await;
        let claims = claims(&exchange(&state).await.unwrap());
        assert_eq!(
            claims.delegation_context,
            DelegationContext::OnBehalfOf {
                actor_client_id: "glance".into(),
                auth_time: claims_auth_time(&claims),
                root_jti: "audit-1".into(),
                project_id: Some("p1".into()),
                delegated_role_ids: Some(vec!["member".into()]),
                application_credential_id: Some("ac1".into()),
            }
        );
        // `admin` is live but not part of the credential.
        assert_eq!(claims.openstack_context.roles, ["member"]);
        assert!(claims.amr.contains(&"application_credential".to_string()));
    }

    fn claims_auth_time(claims: &OpenStackAccessTokenClaims) -> i64 {
        match &claims.delegation_context {
            DelegationContext::OnBehalfOf { auth_time, .. } => *auth_time,
            _ => 0,
        }
    }

    #[tokio::test]
    async fn test_restricted_application_credential_is_not_exchangeable() {
        let issued_at = Utc::now();
        let AuthenticationContext::ApplicationCredential {
            mut application_credential,
            token,
        } = app_cred()
        else {
            unreachable!()
        };
        application_credential.unrestricted = false;
        let state = state(
            Some(subject_vsc(
                AuthenticationContext::ApplicationCredential {
                    application_credential,
                    token,
                },
                issued_at,
                "d1",
            )),
            client(policy(false), "d1"),
            false,
        )
        .await;
        assert!(matches!(
            exchange(&state).await,
            Err(OnBehalfOfError::UnsupportedSubject(_))
        ));
    }

    #[tokio::test]
    async fn test_rescoped_token_keeps_the_parents_auth_time() {
        // The parent was issued 50 minutes ago with the default one hour
        // lifetime; the rescoped token is new but expires with its parent.
        let parent_issued_at = Utc::now() - Duration::minutes(50);
        let rescoped = token_expiring(Utc::now(), parent_issued_at + Duration::hours(1));
        let state = state(
            Some(subject_vsc_with_token(
                AuthenticationContext::Token(rescoped.clone()),
                rescoped,
                "d1",
            )),
            client(policy(false), "d1"),
            false,
        )
        .await;
        let claims = claims(&exchange(&state).await.unwrap());
        let DelegationContext::OnBehalfOf { auth_time, .. } = claims.delegation_context else {
            panic!("not an on-behalf-of context");
        };
        assert!((auth_time - parent_issued_at.timestamp()).abs() <= 1);
    }

    #[tokio::test]
    async fn test_trust_subject_is_not_redelegated() {
        let trust = AuthenticationContext::Trust {
            trust: Trust {
                id: "t1".into(),
                trustor_user_id: "trustor".into(),
                trustee_user_id: "u1".into(),
                project_id: Some("p1".into()),
                ..Default::default()
            },
            token: None,
        };
        let state = state(
            Some(subject_vsc(trust, Utc::now(), "d1")),
            client(policy(false), "d1"),
            false,
        )
        .await;
        assert!(matches!(
            exchange(&state).await,
            Err(OnBehalfOfError::UnsupportedSubject(_))
        ));
    }

    #[tokio::test]
    async fn test_client_must_be_authenticated_for_on_behalf_of() {
        let subject = || {
            Some(subject_vsc(
                AuthenticationContext::Password,
                Utc::now(),
                "d1",
            ))
        };
        // No policy, a policy without the capability, a secret client and a
        // foreign SVID are all `invalid_client`.
        let mut without_capability = client(policy(false), "d1");
        if let Some(d) = without_capability.delegation.as_mut() {
            d.on_behalf_of = false;
        }
        let mut secret = client(policy(false), "d1");
        secret.token_endpoint_auth_method = "client_secret_basic".into();
        for c in [
            client(None, "d1"),
            without_capability,
            secret,
            OAuth2ClientResource {
                spiffe_ids: vec!["spiffe://other/glance".into()],
                ..client(policy(false), "d1")
            },
        ] {
            let state = state(subject(), c, false).await;
            assert!(matches!(
                exchange(&state).await,
                Err(OnBehalfOfError::InvalidClient)
            ));
        }
    }

    #[tokio::test]
    async fn test_operation_lifetime_bounds_the_chain() {
        let issued_at = Utc::now() - Duration::seconds(7200);
        let state = state(
            Some(subject_vsc(
                AuthenticationContext::Password,
                issued_at,
                "d1",
            )),
            client(policy(false), "d1"),
            false,
        )
        .await;
        assert!(matches!(
            exchange(&state).await,
            Err(OnBehalfOfError::OperationExpired)
        ));
    }

    #[tokio::test]
    async fn test_cross_domain_needs_the_opt_in() {
        // A client of another domain.
        let state_without = state(
            Some(subject_vsc(
                AuthenticationContext::Password,
                Utc::now(),
                "d1",
            )),
            client(policy(false), "infra"),
            false,
        )
        .await;
        assert!(matches!(
            exchange(&state_without).await,
            Err(OnBehalfOfError::CrossDomain)
        ));
        let state_with = state(
            Some(subject_vsc(
                AuthenticationContext::Password,
                Utc::now(),
                "d1",
            )),
            client(policy(true), "infra"),
            false,
        )
        .await;
        assert!(exchange(&state_with).await.is_ok());

        // A scope the endpoint's domain does not own is never signed.
        let state_foreign_scope = state(
            Some(subject_vsc(
                AuthenticationContext::Password,
                Utc::now(),
                "d2",
            )),
            client(policy(true), "d1"),
            false,
        )
        .await;
        assert!(matches!(
            exchange(&state_foreign_scope).await,
            Err(OnBehalfOfError::CrossDomain)
        ));
    }

    #[tokio::test]
    async fn test_revoked_root_token_ends_the_chain() {
        let state = state(
            Some(subject_vsc(
                AuthenticationContext::Password,
                Utc::now(),
                "d1",
            )),
            client(policy(false), "d1"),
            true,
        )
        .await;
        assert!(matches!(
            exchange(&state).await,
            Err(OnBehalfOfError::InvalidSubject)
        ));
    }

    #[tokio::test]
    async fn test_invalid_subject_token() {
        let state = state(None, client(policy(false), "d1"), false).await;
        assert!(matches!(
            exchange(&state).await,
            Err(OnBehalfOfError::InvalidSubject)
        ));
    }
}
