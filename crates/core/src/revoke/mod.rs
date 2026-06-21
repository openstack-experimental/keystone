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
//! # Token revocation provider.
//!
//! Token revocation may be implemented in different ways, but in most cases
//! would be represented by the presence of the revocation or the invalidation
//! record matching the certain token parameters.
//!
//! Default backend is the [`sql`](crate::revoke::backend::sql) and uses the
//! database [table](crate::db::entity::revocation_event::Model) for storing the
//! revocation events. They have their own expiration.
//!
//! Tokens are not invalidated by saving the exact value, but rather by saving
//! certain attributes of the token.
//!
//! Following attributes are used for matching of the regular fernet token:
//!
//!   - `audit_id`
//!   - `domain_id`
//!   - `expires_at`
//!   - `project_id`
//!   - `user_id`
//!
//! Additionally the `token.issued_at` is compared to be lower than the
//! `issued_before` field of the revocation record.

pub mod backend;
pub mod error;
pub mod hook;
#[cfg(any(test, feature = "mock"))]
mod provider_api;
pub mod service;
//pub mod types;

use openstack_keystone_core_types::revoke::*;
use openstack_keystone_core_types::token::FernetToken;

use crate::auth::*;
pub use error::RevokeProviderError;
pub use hook::RevokeHook;
#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockRevokeProvider;
pub use provider_api::RevokeApi;
pub use service::RevokeService;

///// Convert Token into the revocation events listing parameters following the
///// <https://openstack-experimental.github.io/keystone/adr/0009-auth-token-revoke.html#revocation-check>.
/// TODO: It is necessary to also consider list of the token roles against the
/// role_id of the entry TODO: domain_id of the database entry should be
/// compared against the user_domain_id and the scope_domain_id. That means,
/// however, that we must resolve the user first.
impl TryFrom<&ValidatedSecurityContext> for RevocationEventListParametersBuilder {
    type Error = RevokeProviderError;
    fn try_from(value: &ValidatedSecurityContext) -> Result<Self, Self::Error> {
        if let Some(token) = value.inner().token() {
            let mut builder = RevocationEventListParametersBuilder::default();
            builder.audit_id(
                token
                    .audit_ids()
                    .first()
                    .ok_or(RevokeProviderError::TokenHasNoAuditId)?,
            );
            builder.issued_before(*token.issued_at());
            if let Some(domain_id) = token.domain_id() {
                builder.domain_ids(vec![domain_id.clone()]);
            }
            if let Some(project_id) = token.project_id() {
                builder.project_id(project_id);
            }
            if let FernetToken::Trust(token) = &token {
                if let AuthenticationContext::Trust { trust, .. } = &value.authentication_context()
                {
                    // Trust tokens include trust, trustor, and trustee user IDs for revocation
                    builder.trust_id(trust.id.clone());
                    builder.user_ids(vec![
                        token.user_id.clone(),
                        trust.trustor_user_id.clone(),
                        trust.trustee_user_id.clone(),
                    ]);
                } else {
                    builder.user_ids(vec![token.user_id.clone()]);
                }
            } else {
                builder.user_ids(vec![token.user_id().clone()]);
            }
            if let Some(authz) = value.authorization()
                && let Some(roles) = authz.effective_roles()
            {
                // For ValidatedSecurityContext from ApplicationCredentials we need to consider
                // original roles tied to the application_credential and not the roles that the
                // effective in the revocation check.
                if let AuthenticationContext::ApplicationCredential {
                    application_credential,
                    ..
                } = &value.authentication_context()
                {
                    builder.role_refs(application_credential.roles.iter());
                } else {
                    builder.role_refs(roles.iter());
                }
            }

            Ok(builder.to_owned())
        } else {
            Err(RevokeProviderError::SecurityContextHasNoToken)
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use std::collections::HashSet;

    use super::*;
    use openstack_keystone_core_types::{
        application_credential::{ApplicationCredential, ApplicationCredentialBuilder},
        resource::*,
        revoke::RevocationEventListParametersBuilder,
        role::*,
        token::{
            FernetToken,
            payload::{ProjectScopePayloadBuilder, TrustPayloadBuilder},
        },
        trust::TrustBuilder,
    };

    fn make_test_principal() -> PrincipalInfo {
        PrincipalInfo {
            identity: IdentityInfo::Principal(
                PrincipalIdentityInfoBuilder::default()
                    .id("spiffe://test/sa")
                    .issuer("https://issuer.test")
                    .domain(
                        DomainBuilder::default()
                            .id("did")
                            .name("test")
                            .enabled(true)
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap(),
            ),
        }
    }

    fn make_test_trust(trustee: &str) -> openstack_keystone_core_types::trust::Trust {
        TrustBuilder::default()
            .id("trust_id")
            .impersonation(false)
            .trustor_user_id("trustor")
            .trustee_user_id(trustee)
            .build()
            .unwrap()
    }

    fn make_test_appcred(user_id: &str, role_ids: Vec<&str>) -> ApplicationCredential {
        ApplicationCredentialBuilder::default()
            .id("app_cred_id")
            .name("test_appcred")
            .project_id("pid")
            .roles(
                role_ids
                    .into_iter()
                    .map(|id| RoleRefBuilder::default().id(id).name(id).build().unwrap())
                    .collect::<Vec<_>>(),
            )
            .unrestricted(false)
            .user_id(user_id)
            .build()
            .unwrap()
    }

    fn make_project() -> Project {
        Project {
            id: "pid".into(),
            domain_id: "did".into(),
            enabled: true,
            name: "proj".into(),
            description: Some("desc".into()),
            is_domain: false,
            ..Default::default()
        }
    }

    fn make_domain() -> Domain {
        Domain {
            id: "did".into(),
            name: "default".into(),
            enabled: true,
            description: None,
            ..Default::default()
        }
    }
    fn make_role<S: Into<String>>(name: S) -> RoleRef {
        let x = name.into();
        RoleRefBuilder::default()
            .id(x.clone())
            .name(x)
            .build()
            .unwrap()
    }

    fn make_vsc_password(token: FernetToken) -> crate::auth::ValidatedSecurityContext {
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_test_principal())
            .build()
            .unwrap();
        let mut sc = crate::auth::SecurityContext::try_from(auth).unwrap();
        sc.set_token(token);
        sc.set_authorization(
            AuthzInfoBuilder::default()
                .scope(ScopeInfo::Project {
                    project: make_project(),
                    project_domain: make_domain(),
                })
                .roles(vec![make_role("r1"), make_role("r2")])
                .build()
                .unwrap(),
        );
        crate::auth::ValidatedSecurityContext::test_new(sc)
    }

    fn make_vsc_trust(
        token: FernetToken,
        trust: openstack_keystone_core_types::trust::Trust,
    ) -> crate::auth::ValidatedSecurityContext {
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Trust { trust, token: None })
            .principal(make_test_principal())
            .build()
            .unwrap();
        let mut sc = crate::auth::SecurityContext::try_from(auth).unwrap();
        sc.set_token(token);
        sc.set_authorization(
            AuthzInfoBuilder::default()
                .scope(ScopeInfo::Project {
                    project: make_project(),
                    project_domain: make_domain(),
                })
                .roles(vec![make_role("r1"), make_role("r2")])
                .build()
                .unwrap(),
        );
        crate::auth::ValidatedSecurityContext::test_new(sc)
    }

    fn make_vsc_appcred(
        token: FernetToken,
        app_cred: ApplicationCredential,
    ) -> crate::auth::ValidatedSecurityContext {
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::ApplicationCredential {
                application_credential: app_cred.clone(),
                token: None,
            })
            .principal(make_test_principal())
            .build()
            .unwrap();
        let mut sc = crate::auth::SecurityContext::try_from(auth).unwrap();
        sc.set_token(token);
        sc.set_authorization(
            AuthzInfoBuilder::default()
                .scope(ScopeInfo::Project {
                    project: make_project(),
                    project_domain: make_domain(),
                })
                .roles(app_cred.roles.clone())
                .build()
                .unwrap(),
        );
        crate::auth::ValidatedSecurityContext::test_new(sc)
    }

    fn make_project_scope_token(user_id: &str, project_id: &str) -> FernetToken {
        let payload = ProjectScopePayloadBuilder::default()
            .methods(vec!["password".to_string()].into_iter())
            .audit_ids(vec!["test_audit_id".to_string()].into_iter())
            .user_id(user_id)
            .project_id(project_id)
            .expires_at(Utc::now() + chrono::TimeDelta::hours(1))
            .build()
            .unwrap();
        FernetToken::ProjectScope(payload)
    }

    fn make_trust_scope_token(user_id: &str, trust_id: &str) -> FernetToken {
        let payload = TrustPayloadBuilder::default()
            .methods(vec!["trust".to_string()].into_iter())
            .audit_ids(vec!["test_audit_id".to_string()].into_iter())
            .user_id(user_id)
            .trust_id(trust_id)
            .project_id("pid")
            .expires_at(Utc::now() + chrono::TimeDelta::hours(1))
            .build()
            .unwrap();
        FernetToken::Trust(payload)
    }

    #[test]
    fn test_revocation_list_project_scope() {
        let token = make_project_scope_token("user_id", "project_id");
        let vsc = make_vsc_password(token.clone());

        let params_builder = RevocationEventListParametersBuilder::try_from(&vsc).unwrap();
        let params = params_builder.build().unwrap();

        assert_eq!(params.audit_id, Some("test_audit_id".to_string()));
        assert_eq!(params.project_id, Some("project_id".to_string()));
        assert_eq!(params.user_ids, Some(vec!["user_id".to_string()]));
        assert!(params.trust_id.is_none());
        assert_eq!(
            HashSet::<String>::from_iter(["r1".to_string(), "r2".to_string()]),
            HashSet::<String>::from_iter(params.role_ids.expect("roles must be there").into_iter())
        );
    }

    #[test]
    fn test_revocation_list_trust_scope() {
        let trust = make_test_trust("trustee_user");
        let token = make_trust_scope_token("token_user", "trust_id");
        let vsc = make_vsc_trust(token, trust);

        let params_builder = RevocationEventListParametersBuilder::try_from(&vsc).unwrap();
        let params = params_builder.build().unwrap();

        assert_eq!(params.trust_id, Some("trust_id".to_string()));
        assert!(
            params
                .user_ids
                .as_ref()
                .is_some_and(|vec| vec.iter().any(|s| s == "token_user"))
        );
        assert!(
            params
                .user_ids
                .as_ref()
                .is_some_and(|vec| vec.iter().any(|s| s == "trustor"))
        );
        assert!(
            params
                .user_ids
                .as_ref()
                .is_some_and(|vec| vec.iter().any(|s| s == "trustee_user"))
        );
        assert_eq!(
            HashSet::<String>::from_iter(["r1".to_string(), "r2".to_string()]),
            HashSet::<String>::from_iter(params.role_ids.expect("roles must be there").into_iter())
        );
    }

    #[test]
    fn test_revocation_list_application_credential_roles() {
        let token = make_project_scope_token("user_id", "pid");

        let app_cred = make_test_appcred("user_id", vec!["role1", "role2"]);
        let vsc = make_vsc_appcred(token, app_cred);

        let params_builder = RevocationEventListParametersBuilder::try_from(&vsc).unwrap();
        let params = params_builder.build().unwrap();

        assert_eq!(params.audit_id, Some("test_audit_id".to_string()));
        assert_eq!(params.project_id, Some("pid".to_string()));
        assert_eq!(params.user_ids, Some(vec!["user_id".to_string()]));
        assert_eq!(
            HashSet::<String>::from_iter(["role1".to_string(), "role2".to_string()]),
            HashSet::<String>::from_iter(params.role_ids.expect("roles must be there").into_iter())
        );
    }

    #[test]
    fn test_revocation_list_no_token_fails() {
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_test_principal())
            .build()
            .unwrap();
        let sc = crate::auth::SecurityContext::try_from(auth).unwrap();
        let vsc = crate::auth::ValidatedSecurityContext::test_new(sc);

        let result = RevocationEventListParametersBuilder::try_from(&vsc);
        assert!(matches!(
            result,
            Err(RevokeProviderError::SecurityContextHasNoToken)
        ));
    }
}
