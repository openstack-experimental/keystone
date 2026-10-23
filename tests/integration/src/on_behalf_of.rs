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
//! # On-behalf-of exchange integration tests (ADR 0036 phase 2)
//!
//! Raft-only backend, like the service grant suite (the `on_behalf_of`
//! filter in `.config/nextest.toml`). A user's real Keystone token is
//! exchanged by a registered `tls_client_auth` service, the result is
//! signed with the domain's real key and exchanged again, and the chain is
//! cut by revoking the root token, removing a role or letting the client's
//! operation lifetime pass.

use chrono::Utc;
use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_client::on_behalf_of::{
    ExchangedOnBehalfOf, OnBehalfOfError, OnBehalfOfRequest, OnBehalfOfSubject,
    build_on_behalf_of_claims, exchange_on_behalf_of,
};
use openstack_keystone_core_types::assignment::{Assignment, AssignmentType};
use openstack_keystone_core_types::auth::AuthenticationError;
use openstack_keystone_core_types::oauth2_client::{
    Audience, DelegationContext, DelegationPolicy, OAuth2ClientResource,
    OAuth2ClientResourceCreateBuilder,
};
use openstack_keystone_key_repository::asymmetric::{
    SigningAlgorithm, derive_kid, jwt_algorithm, to_encoding_key,
};

use crate::assignment::grant_role_to_user_on_project;
use crate::service_grant::{TRUST_DOMAIN, get_grant_state, svid, user_context};
use crate::{create_domain, create_project, create_role, create_user};
use openstack_keystone_core::oauth2_client::bound_bearer::{
    BoundBearerError, authenticate_bound_bearer,
};

const ISSUER: &str = "https://ks.example/v4/oauth2";

/// Register a delegatable service allowed to exchange on behalf of users.
async fn register_service(
    state: &ServiceState,
    domain_id: &str,
    max_operation_lifetime: u64,
) -> Result<OAuth2ClientResource> {
    let provider_id = format!("svc-{}", Uuid::new_v4().simple());
    let (client, _) = state
        .provider
        .get_oauth2_client_provider()
        .create(
            &ExecutionContext::internal(state),
            OAuth2ClientResourceCreateBuilder::default()
                .client_id("")
                .provider_id(provider_id.clone())
                .domain_id(domain_id)
                .name("Integration service")
                .token_endpoint_auth_method("tls_client_auth")
                .grant_types(vec![])
                .require_pkce(false)
                .spiffe_ids(vec![format!(
                    "spiffe://{TRUST_DOMAIN}/service/{provider_id}/host/*"
                )])
                .delegation(DelegationPolicy {
                    on_behalf_of: true,
                    max_operation_lifetime: Some(max_operation_lifetime),
                    ..Default::default()
                })
                .build()?,
            false,
        )
        .await?;
    Ok(client)
}

async fn exchange(
    state: &ServiceState,
    domain_id: &str,
    client: &OAuth2ClientResource,
    subject: OnBehalfOfSubject<'_>,
) -> Result<ExchangedOnBehalfOf, OnBehalfOfError> {
    let svid = svid(client);
    let issuer = format!("{ISSUER}/{domain_id}");
    exchange_on_behalf_of(
        state,
        &OnBehalfOfRequest {
            domain_id,
            issuer: &issuer,
            signing_algorithm: SigningAlgorithm::Es256,
            svid: &svid,
            client_id: &client.client_id,
            subject,
        },
    )
    .await
}

/// Build the hop token the endpoint would return and sign it with the
/// domain's real key.
async fn mint_hop(
    state: &ServiceState,
    domain_id: &str,
    exchanged: &ExchangedOnBehalfOf,
) -> Result<String> {
    let now = Utc::now().timestamp();
    let claims = build_on_behalf_of_claims(
        exchanged,
        &format!("{ISSUER}/{domain_id}"),
        Uuid::new_v4().to_string(),
        now,
        now + 300,
        Audience::control_plane(),
    )?;
    let key = state
        .provider
        .get_oauth2_key_provider()
        .active_signing_key(state, domain_id)
        .await?;
    let mut header = jsonwebtoken::Header::new(jwt_algorithm(key.algorithm));
    header.kid = Some(derive_kid(&key.public_key_der));
    Ok(jsonwebtoken::encode(
        &header,
        &claims,
        &to_encoding_key(&key)?,
    )?)
}

struct Fixture {
    state: ServiceState,
    _tmp: tempfile::TempDir,
    domain_id: String,
    client: OAuth2ClientResource,
    user_id: String,
    project_id: String,
    role_id: String,
    token: openstack_keystone_core_types::token::FernetToken,
    encoded: String,
    // Keep the resources alive for the duration of the test.
    _guards: (
        crate::common::AsyncResourceGuard<
            openstack_keystone_core_types::identity::UserResponse,
            ServiceState,
        >,
        crate::common::AsyncResourceGuard<
            openstack_keystone_core_types::resource::Project,
            ServiceState,
        >,
        crate::common::AsyncResourceGuard<openstack_keystone_core_types::role::Role, ServiceState>,
    ),
}

/// One user with a role on one project, holding a real project-scoped
/// token, and one service allowed to exchange on behalf of users.
async fn fixture(max_operation_lifetime: u64) -> Result<Fixture> {
    let (state, tmp) = get_grant_state().await?;
    let domain = create_domain!(state)?;
    state
        .provider
        .get_oauth2_key_provider()
        .ensure_domain_keys(&state, &domain.id)
        .await?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role.id).await?;
    let client = register_service(&state, &domain.id, max_operation_lifetime).await?;
    let vsc = user_context(&state, &user, &project).await?;
    let token = vsc.token()?.clone();
    let encoded = state.provider.get_token_provider().encode_token(&token)?;
    Ok(Fixture {
        domain_id: domain.id.clone(),
        client,
        user_id: user.id.clone(),
        project_id: project.id.clone(),
        role_id: role.id.clone(),
        token,
        encoded,
        state,
        _tmp: tmp,
        _guards: (user, project, role),
    })
}

#[tokio::test]
#[traced_test]
async fn test_exchange_and_reexchange_keep_the_chain() -> Result<()> {
    let f = fixture(3600).await?;
    let first = exchange(
        &f.state,
        &f.domain_id,
        &f.client,
        OnBehalfOfSubject::Keystone(&f.encoded),
    )
    .await?;
    let hop = mint_hop(&f.state, &f.domain_id, &first).await?;

    let second = exchange(
        &f.state,
        &f.domain_id,
        &f.client,
        OnBehalfOfSubject::Hop(&hop),
    )
    .await?;
    let now = Utc::now().timestamp();
    let (first, second) = (
        build_on_behalf_of_claims(
            &first,
            "i",
            "j".into(),
            now,
            now + 1,
            Audience::control_plane(),
        )?,
        build_on_behalf_of_claims(
            &second,
            "i",
            "j".into(),
            now,
            now + 1,
            Audience::control_plane(),
        )?,
    );
    // The chain is fixed by the first hop and the user stays the subject.
    assert_eq!(first.delegation_context, second.delegation_context);
    assert!(matches!(
        &second.delegation_context,
        DelegationContext::OnBehalfOf { root_jti, project_id: None, .. }
            if Some(root_jti) == f.token.audit_ids().first()
    ));
    assert_eq!(second.sub, f.user_id);
    // `on_behalf_of` appears once however often the chain is exchanged.
    assert_eq!(
        second.amr.iter().filter(|m| *m == "on_behalf_of").count(),
        1
    );
    assert_eq!(first.amr, second.amr);
    assert!(second.openstack_context.roles.len() == first.openstack_context.roles.len());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_revoking_the_root_token_ends_the_chain() -> Result<()> {
    let f = fixture(3600).await?;
    let first = exchange(
        &f.state,
        &f.domain_id,
        &f.client,
        OnBehalfOfSubject::Keystone(&f.encoded),
    )
    .await?;
    let hop = mint_hop(&f.state, &f.domain_id, &first).await?;

    f.state
        .provider
        .get_revoke_provider()
        .revoke_token(&ExecutionContext::internal(&f.state), &f.token)
        .await?;

    // Neither the user's token nor the hop derived from it exchanges.
    assert!(matches!(
        exchange(
            &f.state,
            &f.domain_id,
            &f.client,
            OnBehalfOfSubject::Hop(&hop)
        )
        .await,
        Err(OnBehalfOfError::InvalidSubject)
    ));
    assert!(matches!(
        exchange(
            &f.state,
            &f.domain_id,
            &f.client,
            OnBehalfOfSubject::Keystone(&f.encoded)
        )
        .await,
        Err(OnBehalfOfError::InvalidSubject)
    ));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_losing_the_role_ends_the_chain() -> Result<()> {
    let f = fixture(3600).await?;
    let first = exchange(
        &f.state,
        &f.domain_id,
        &f.client,
        OnBehalfOfSubject::Keystone(&f.encoded),
    )
    .await?;
    let hop = mint_hop(&f.state, &f.domain_id, &first).await?;

    f.state
        .provider
        .get_assignment_provider()
        .revoke_grant(
            &ExecutionContext::internal(&f.state),
            Assignment {
                actor_id: f.user_id.clone(),
                role_id: f.role_id.clone(),
                role_name: None,
                target_id: f.project_id.clone(),
                r#type: AssignmentType::UserProject,
                inherited: false,
                implied_via: None,
            },
        )
        .await?;

    assert!(matches!(
        exchange(
            &f.state,
            &f.domain_id,
            &f.client,
            OnBehalfOfSubject::Hop(&hop)
        )
        .await,
        Err(OnBehalfOfError::Authentication(
            AuthenticationError::ActorHasNoRolesOnTarget
        ))
    ));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_a_hop_token_belongs_to_one_client() -> Result<()> {
    let f = fixture(3600).await?;
    let first = exchange(
        &f.state,
        &f.domain_id,
        &f.client,
        OnBehalfOfSubject::Keystone(&f.encoded),
    )
    .await?;
    let hop = mint_hop(&f.state, &f.domain_id, &first).await?;

    // Another service holding the token cannot continue the chain.
    let other = register_service(&f.state, &f.domain_id, 3600).await?;
    assert!(matches!(
        exchange(&f.state, &f.domain_id, &other, OnBehalfOfSubject::Hop(&hop)).await,
        Err(OnBehalfOfError::UnsupportedSubject(_))
    ));

    // An unknown client cannot start a chain.
    let mut plain = f.client.clone();
    plain.client_id = "does-not-exist".into();
    assert!(
        exchange(
            &f.state,
            &f.domain_id,
            &plain,
            OnBehalfOfSubject::Keystone(&f.encoded)
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_operation_lifetime_ends_the_chain() -> Result<()> {
    let f = fixture(2).await?;
    let first = exchange(
        &f.state,
        &f.domain_id,
        &f.client,
        OnBehalfOfSubject::Keystone(&f.encoded),
    )
    .await?;
    let hop = mint_hop(&f.state, &f.domain_id, &first).await?;

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(matches!(
        exchange(
            &f.state,
            &f.domain_id,
            &f.client,
            OnBehalfOfSubject::Hop(&hop)
        )
        .await,
        Err(OnBehalfOfError::OperationExpired)
    ));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_bound_bearer_hop_is_accepted_only_with_the_actors_svid() -> Result<()> {
    let f = fixture(3600).await?;
    let first = exchange(
        &f.state,
        &f.domain_id,
        &f.client,
        OnBehalfOfSubject::Keystone(&f.encoded),
    )
    .await?;
    let hop = mint_hop(&f.state, &f.domain_id, &first).await?;

    // Keystone's own API takes the hop token together with the actor's SVID,
    // and a service holding the user's token is a delegated caller.
    let vsc = authenticate_bound_bearer(&f.state, &svid(&f.client), &hop).await?;
    assert!(vsc.authentication_context().is_delegated());
    assert!(matches!(
        vsc.authentication_context(),
        openstack_keystone_core_types::auth::AuthenticationContext::OnBehalfOf { .. }
    ));

    let other = register_service(&f.state, &f.domain_id, 3600).await?;
    assert!(matches!(
        authenticate_bound_bearer(&f.state, &svid(&other), &hop).await,
        Err(BoundBearerError::NotBound(_))
    ));

    // Revoking the root token ends the chain on this API too.
    f.state
        .provider
        .get_revoke_provider()
        .revoke_token(&ExecutionContext::internal(&f.state), &f.token)
        .await?;
    assert!(matches!(
        authenticate_bound_bearer(&f.state, &svid(&f.client), &hop).await,
        Err(BoundBearerError::NotBound(_))
    ));
    Ok(())
}

/// A project-scoped token authenticated by a fresh unrestricted application
/// credential of the fixture user, and the credential.
async fn app_cred_token(
    f: &Fixture,
) -> Result<(
    String,
    openstack_keystone_core_types::application_credential::ApplicationCredentialCreateResponse,
)> {
    use openstack_keystone::auth::*;
    use openstack_keystone_core_types::application_credential::ApplicationCredentialCreate;
    use openstack_keystone_core_types::resource::{DomainBuilder, ProjectBuilder};
    use openstack_keystone_core_types::role::RoleRefBuilder;

    let cred = f
        .state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &ExecutionContext::internal(&f.state),
            ApplicationCredentialCreate {
                name: Uuid::new_v4().to_string(),
                project_id: f.project_id.clone(),
                roles: vec![RoleRefBuilder::default().id(f.role_id.clone()).build()?],
                unrestricted: Some(true),
                user_id: f.user_id.clone(),
                ..Default::default()
            },
        )
        .await?;
    let user = f
        .state
        .provider
        .get_identity_provider()
        .get_user(&ExecutionContext::internal(&f.state), &f.user_id)
        .await?
        .ok_or_else(|| eyre::eyre!("fixture user is gone"))?;
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::ApplicationCredential {
            application_credential: cred.clone().into(),
            token: None,
        })
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(f.user_id.clone())
                    .user(user)
                    .build()?,
            ),
        })
        .build()?;
    let vsc = f
        .state
        .provider
        .get_token_provider()
        .issue_token_context(
            &ExecutionContext::internal(&f.state),
            &SecurityContext::try_from(auth)?,
            &ScopeInfo::Project {
                project: ProjectBuilder::default()
                    .id(f.project_id.clone())
                    .name(f.project_id.clone())
                    .domain_id(f.domain_id.clone())
                    .enabled(true)
                    .build()?,
                project_domain: DomainBuilder::default()
                    .id(f.domain_id.clone())
                    .name(f.domain_id.clone())
                    .enabled(true)
                    .build()?,
            },
        )
        .await?;
    let encoded = f
        .state
        .provider
        .get_token_provider()
        .encode_token(vsc.token()?)?;
    Ok((encoded, cred))
}

#[tokio::test]
#[traced_test]
async fn test_deleting_the_application_credential_ends_the_chain() -> Result<()> {
    let f = fixture(3600).await?;
    let (encoded, cred) = app_cred_token(&f).await?;
    let first = exchange(
        &f.state,
        &f.domain_id,
        &f.client,
        OnBehalfOfSubject::Keystone(&encoded),
    )
    .await?;
    let hop = mint_hop(&f.state, &f.domain_id, &first).await?;
    // The chain keeps working while the credential does.
    exchange(
        &f.state,
        &f.domain_id,
        &f.client,
        OnBehalfOfSubject::Hop(&hop),
    )
    .await?;
    authenticate_bound_bearer(&f.state, &svid(&f.client), &hop).await?;

    // Removing the record ends the chain even though the tokens issued from
    // it were not revoked.
    f.state
        .provider
        .get_application_credential_provider()
        .delete_application_credential(&ExecutionContext::internal(&f.state), cred.into())
        .await?;
    assert!(matches!(
        exchange(
            &f.state,
            &f.domain_id,
            &f.client,
            OnBehalfOfSubject::Hop(&hop)
        )
        .await,
        Err(OnBehalfOfError::InvalidSubject)
    ));
    assert!(matches!(
        authenticate_bound_bearer(&f.state, &svid(&f.client), &hop).await,
        Err(BoundBearerError::NotBound(_))
    ));
    Ok(())
}

/// Claims of a plain user JWT the OAuth2 provider issued, derived from the
/// claims of a chain's first hop so every other field is valid.
fn plain_user_claims(
    first: &ExchangedOnBehalfOf,
    domain_id: &str,
    amr: Vec<String>,
) -> Result<openstack_keystone_core_types::oauth2_client::OpenStackAccessTokenClaims> {
    let now = Utc::now().timestamp();
    let mut claims = build_on_behalf_of_claims(
        first,
        &format!("{ISSUER}/{domain_id}"),
        Uuid::new_v4().to_string(),
        now,
        now + 300,
        Audience::control_plane(),
    )?;
    claims.delegation_context = DelegationContext::Plain;
    claims.act = None;
    claims.amr = amr;
    Ok(claims)
}

#[tokio::test]
#[traced_test]
async fn test_a_plain_user_jwt_starts_a_chain() -> Result<()> {
    let f = fixture(3600).await?;
    let seed = exchange(
        &f.state,
        &f.domain_id,
        &f.client,
        OnBehalfOfSubject::Keystone(&f.encoded),
    )
    .await?;
    let claims = plain_user_claims(&seed, &f.domain_id, vec!["password".into()])?;
    let jwt = crate::service_grant::sign_claims(&f.state, &f.domain_id, &claims).await?;

    // The user's JWT is exchangeable like a Keystone token, and is the root.
    let first = exchange(
        &f.state,
        &f.domain_id,
        &f.client,
        OnBehalfOfSubject::Hop(&jwt),
    )
    .await?;
    let hop = mint_hop(&f.state, &f.domain_id, &first).await?;
    exchange(
        &f.state,
        &f.domain_id,
        &f.client,
        OnBehalfOfSubject::Hop(&hop),
    )
    .await?;
    // The same JWT is not a Keystone credential on its own.
    assert!(matches!(
        authenticate_bound_bearer(&f.state, &svid(&f.client), &jwt).await,
        Err(BoundBearerError::NotDelegated)
    ));

    // Revoking the JWT ends the chain, including the hops already minted.
    f.state
        .provider
        .get_oauth2_key_provider()
        .revoke_jti(&f.state, &f.domain_id, &claims.jti, claims.exp)
        .await?;
    for subject in [&jwt, &hop] {
        assert!(matches!(
            exchange(
                &f.state,
                &f.domain_id,
                &f.client,
                OnBehalfOfSubject::Hop(subject)
            )
            .await,
            Err(OnBehalfOfError::InvalidSubject)
        ));
    }
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_a_service_credentials_jwt_is_not_exchangeable() -> Result<()> {
    let f = fixture(3600).await?;
    let seed = exchange(
        &f.state,
        &f.domain_id,
        &f.client,
        OnBehalfOfSubject::Keystone(&f.encoded),
    )
    .await?;
    let claims = plain_user_claims(&seed, &f.domain_id, vec!["client_credentials".into()])?;
    let jwt = crate::service_grant::sign_claims(&f.state, &f.domain_id, &claims).await?;
    assert!(matches!(
        exchange(
            &f.state,
            &f.domain_id,
            &f.client,
            OnBehalfOfSubject::Hop(&jwt)
        )
        .await,
        Err(OnBehalfOfError::UnsupportedSubject(_))
    ));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_introspection_sees_the_chain_end() -> Result<()> {
    use openstack_keystone_core::oauth2_client::on_behalf_of::is_chain_live;

    let f = fixture(3600).await?;
    let first = exchange(
        &f.state,
        &f.domain_id,
        &f.client,
        OnBehalfOfSubject::Keystone(&f.encoded),
    )
    .await?;
    let hop = mint_hop(&f.state, &f.domain_id, &first).await?;
    let issuer = format!("{ISSUER}/{}", f.domain_id);
    let live = || {
        is_chain_live(
            &f.state,
            &f.domain_id,
            &issuer,
            SigningAlgorithm::Es256,
            &f.client.client_id,
            &hop,
        )
    };
    assert!(live().await);

    // Revoking the user's token ends the chain for a resource server that
    // asks, although the hop token itself is neither expired nor revoked.
    f.state
        .provider
        .get_revoke_provider()
        .revoke_token(&ExecutionContext::internal(&f.state), &f.token)
        .await?;
    assert!(!live().await);
    Ok(())
}
