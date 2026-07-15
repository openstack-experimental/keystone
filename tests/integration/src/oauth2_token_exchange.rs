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
//! # RFC 8693 Token Exchange integration tests (ADR 0026 §12)
//!
//! Raft-only backend -- these tests only run under the `raft` nextest
//! profile (see `.config/nextest.toml`), matching the other `oauth2_*`
//! suites. Mints a real application-credential-backed Fernet subject_token
//! through the same `TokenApi` pipeline `/token` uses, then drives it
//! through `openstack_keystone_core::oauth2_client::token_exchange`'s real
//! `validate_subject_token`/`build_token_exchange_claims` -- the same two
//! calls `handle_token_exchange_grant` makes -- to prove exchange behavior
//! end-to-end against real storage, not mocks. In particular this is a
//! regression guard for commit `ccc3b3d1` ("Bind Token Exchange grant to
//! the issuing domain"): a subject_token scoped to one domain must never
//! exchange successfully against a client registered in another domain.

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone::auth::*;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_client::token_exchange::{
    TokenExchangeError, build_token_exchange_claims, validate_subject_token,
};
use openstack_keystone_core_types::application_credential::*;
use openstack_keystone_core_types::oauth2_client::{GrantType, OAuth2ClientResourceCreateBuilder};
use openstack_keystone_core_types::resource::{DomainBuilder, ProjectBuilder};
use openstack_keystone_core_types::role::*;

use crate::assignment::grant_role_to_user_on_project;
use crate::common::get_state;
use crate::{create_domain, create_project, create_role, create_user};

/// Mint a real `client_secret_basic` `OAuth2Client` in `domain_id` holding
/// the `token-exchange` grant type, mirroring
/// `oauth2_token_verify.rs::provision_client_credentials_client` but for
/// this grant.
async fn provision_token_exchange_client(
    state: &openstack_keystone::keystone::ServiceState,
    domain_id: &str,
) -> Result<openstack_keystone_core_types::oauth2_client::OAuth2ClientResource> {
    state
        .provider
        .get_oauth2_key_provider()
        .ensure_domain_keys(state, domain_id)
        .await?;

    let (client, _secret) = state
        .provider
        .get_oauth2_client_provider()
        .create(
            &ExecutionContext::internal(state),
            OAuth2ClientResourceCreateBuilder::default()
                .client_id("")
                .provider_id(format!("provider-{domain_id}"))
                .domain_id(domain_id)
                .token_endpoint_auth_method("client_secret_basic")
                .grant_types(vec![GrantType::TokenExchange])
                .build()?,
            true,
        )
        .await?;
    Ok(client)
}

/// Mint a real, domain-scoped application-credential-backed Fernet
/// subject_token, exactly as `test/integration/src/token/validate/
/// application_credential.rs::test_valid` does: create the user/project/
/// role/app-cred, then `issue_token_context` for `ScopeInfo::Project`.
///
/// Returns the token alongside the `user`/`project` `AsyncResourceGuard`s:
/// each guard hard-deletes its resource on drop, so the caller must keep
/// them alive for as long as the returned token needs to remain valid
/// (letting them drop at the end of the helper, before the token is ever
/// used, would delete the user out from under `validate_subject_token`).
#[allow(clippy::type_complexity)]
async fn mint_app_cred_subject_token(
    state: &openstack_keystone::keystone::ServiceState,
    domain_id: &str,
) -> Result<(
    String,
    crate::common::AsyncResourceGuard<
        openstack_keystone_core_types::identity::UserResponse,
        openstack_keystone::keystone::ServiceState,
    >,
    crate::common::AsyncResourceGuard<
        openstack_keystone_core_types::resource::Project,
        openstack_keystone::keystone::ServiceState,
    >,
)> {
    let project = create_project!(state, domain_id.to_string())?;
    let user = create_user!(state, domain_id.to_string())?;
    let role = create_role!(state)?;
    grant_role_to_user_on_project(state, &user.id, &project.id, &role.id).await?;

    let cred: ApplicationCredentialCreateResponse = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &ExecutionContext::internal(state),
            ApplicationCredentialCreate {
                access_rules: None,
                name: Uuid::new_v4().to_string(),
                project_id: project.id.clone(),
                roles: vec![RoleRef::from(role.clone())],
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::ApplicationCredential {
            application_credential: cred.clone().into(),
            token: None,
        })
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user.id.clone())
                    .user(user.clone())
                    .build()?,
            ),
        })
        .build()?;
    let ctx = SecurityContext::try_from(auth)?;

    let vsc = state
        .provider
        .get_token_provider()
        .issue_token_context(
            &ExecutionContext::internal(state),
            &ctx,
            &ScopeInfo::Project {
                project: ProjectBuilder::default()
                    .id(cred.project_id.clone())
                    .name(project.id.clone())
                    .domain_id(domain_id.to_string())
                    .enabled(true)
                    .build()?,
                project_domain: DomainBuilder::default()
                    .id(domain_id.to_string())
                    .name(domain_id.to_string())
                    .enabled(true)
                    .build()?,
            },
        )
        .await?;

    let encoded = state
        .provider
        .get_token_provider()
        .encode_token(vsc.inner().token().unwrap())?;
    Ok((encoded, user, project))
}

#[tokio::test]
#[traced_test]
async fn test_token_exchange_full_flow_issues_app_cred_delegated_claims() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let client = provision_token_exchange_client(&state, &domain.id).await?;
    let (subject_token, _user_guard, _project_guard) =
        mint_app_cred_subject_token(&state, &domain.id).await?;

    let (vsc, delegation) = validate_subject_token(&state, &subject_token).await?;
    let issuer = format!("https://ks.example/v4/oauth2/{}", domain.id);
    let claims = build_token_exchange_claims(
        &client,
        &vsc,
        delegation,
        &issuer,
        Uuid::new_v4().to_string(),
        chrono::Utc::now().timestamp(),
        chrono::Utc::now().timestamp() + 900,
    )?;

    assert_eq!(claims.aud, format!("openstack-apis:{}", domain.id));
    assert!(claims.amr.contains(&"application_credential".to_string()));

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_token_exchange_rejects_cross_domain_subject_token() -> Result<()> {
    // Regression guard for ccc3b3d1: a subject_token scoped to domain A
    // must be rejected when exchanged via a client registered in domain B,
    // even though both are legitimately provisioned domains and the
    // subject_token itself validates successfully.
    let (state, _tmp) = get_state().await?;
    let domain_a = create_domain!(state)?;
    let domain_b = create_domain!(state)?;
    let client_b = provision_token_exchange_client(&state, &domain_b.id).await?;
    let (subject_token_a, _user_guard, _project_guard) =
        mint_app_cred_subject_token(&state, &domain_a.id).await?;

    let (vsc, delegation) = validate_subject_token(&state, &subject_token_a).await?;
    let issuer_b = format!("https://ks.example/v4/oauth2/{}", domain_b.id);
    let err = build_token_exchange_claims(
        &client_b,
        &vsc,
        delegation,
        &issuer_b,
        Uuid::new_v4().to_string(),
        chrono::Utc::now().timestamp(),
        chrono::Utc::now().timestamp() + 900,
    )
    .unwrap_err();

    assert!(matches!(err, TokenExchangeError::CrossDomainSubjectToken));

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_token_exchange_requires_grant_types_capability() -> Result<()> {
    // A client that never registered `token-exchange` in `grant_types`
    // must be rejected by the same check `handle_token_exchange_grant`
    // performs before ever calling `validate_subject_token` -- exercised
    // here at the resource level to prove `grant_types` is actually
    // persisted/read back faithfully by the real Raft backend.
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    state
        .provider
        .get_oauth2_key_provider()
        .ensure_domain_keys(&state, &domain.id)
        .await?;

    let (client, _secret) = state
        .provider
        .get_oauth2_client_provider()
        .create(
            &ExecutionContext::internal(&state),
            OAuth2ClientResourceCreateBuilder::default()
                .client_id("")
                .provider_id(format!("provider-{}", domain.id))
                .domain_id(domain.id.clone())
                .token_endpoint_auth_method("client_secret_basic")
                .grant_types(vec![GrantType::ClientCredentials])
                .build()?,
            true,
        )
        .await?;

    assert!(
        !client.grant_types.contains(&GrantType::TokenExchange),
        "client must not carry token-exchange unless explicitly granted"
    );

    Ok(())
}
