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

use super::*;
use chrono::Duration;
use std::collections::HashMap;

use crate::application_credential::ApplicationCredentialBuilder;
use crate::assignment::{AssignmentBuilder, AssignmentType};
use crate::identity::UserOptions;
use crate::role::RoleRefBuilder;
use crate::token::FernetToken;
use crate::token::TokenRestrictionBuilder;
use crate::token::payload::TrustPayloadBuilder;
use crate::token::payload::UnscopedPayloadBuilder;
use crate::trust::*;

// --- Fixture builders ---

fn make_user(uid: &str, enabled: bool) -> UserResponse {
    UserResponse {
        id: uid.to_string(),
        enabled,
        default_project_id: None,
        domain_id: "did".into(),
        extra: HashMap::new(),
        name: "foo".into(),
        options: UserOptions::default(),
        federated: None,
        password_expires_at: None,
    }
}

fn make_enabled_user(uid: &str) -> UserIdentityInfo {
    UserIdentityInfoBuilder::default()
        .user_id(uid)
        .user(make_user(uid, true))
        .user_domain(make_domain())
        .build()
        .unwrap()
}

fn make_disabled_user(uid: &str) -> UserIdentityInfo {
    UserIdentityInfoBuilder::default()
        .user_id(uid)
        .user(make_user(uid, false))
        .user_domain(make_domain())
        .build()
        .unwrap()
}

fn make_principal(uid: &str) -> PrincipalInfo {
    PrincipalInfo {
        identity: IdentityInfo::User(make_enabled_user(uid)),
    }
}

fn make_project() -> Project {
    Project {
        id: "pid".into(),
        domain_id: "did".into(),
        enabled: true,
        name: "proj".into(),
        description: Some("desc".into()),
        is_domain: false,
        parent_id: None,
        extra: HashMap::new(),
    }
}

fn make_disabled_project() -> Project {
    Project {
        id: "pid".into(),
        domain_id: "did".into(),
        enabled: false,
        name: "proj".into(),
        ..Default::default()
    }
}

fn make_project2() -> Project {
    Project {
        id: "pid2".into(),
        domain_id: "did".into(),
        enabled: true,
        name: "proj2".into(),
        ..Default::default()
    }
}

fn make_domain() -> Domain {
    Domain {
        id: "did".into(),
        name: "default".into(),
        enabled: true,
        description: None,
        extra: HashMap::new(),
    }
}

fn make_disabled_domain() -> Domain {
    Domain {
        id: "did".into(),
        name: "default".into(),
        enabled: false,
        description: None,
        extra: HashMap::new(),
    }
}

fn make_trust_with_project(pid: &str) -> Trust {
    TrustBuilder::default()
        .id("trust_id")
        .trustor_user_id("trustor")
        .trustee_user_id("trustee")
        .project_id(pid)
        .impersonation(false)
        .build()
        .unwrap()
}

fn make_token_restriction(pid: &str) -> TokenRestriction {
    TokenRestrictionBuilder::default()
        .allow_rescope(true)
        .allow_renew(true)
        .id("tr_id")
        .domain_id("did")
        .role_ids(vec![])
        .project_id(pid)
        .build()
        .unwrap()
}

fn admin_role() -> RoleRef {
    RoleRefBuilder::default()
        .id("admin")
        .name("admin")
        .build()
        .unwrap()
}

/// Pre-built scopes used by every scope-boundaries test.
struct AllScopes {
    project: ScopeInfo,
    project2: ScopeInfo,
    domain: ScopeInfo,
    trust: ScopeInfo,
    system: ScopeInfo,
    unscoped: ScopeInfo,
}

impl AllScopes {
    fn new() -> Self {
        // Trust scope without project (generic trust)
        let trust = TrustBuilder::default()
            .id("trust_id")
            .trustor_user_id("trustor")
            .trustee_user_id("trustee")
            .impersonation(false)
            .build()
            .unwrap();
        Self {
            project: ScopeInfo::Project {
                project: make_project(),
                project_domain: make_domain(),
            },
            project2: ScopeInfo::Project {
                project: make_project2(),
                project_domain: make_domain(),
            },
            domain: ScopeInfo::Domain(make_domain().clone()),
            trust: ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
                trust: trust.clone(),
                project: make_project(),
                project_domain: make_domain(),
            })),
            system: ScopeInfo::System("all".into()),
            unscoped: ScopeInfo::Unscoped,
        }
    }
}

// --- Test helpers for AuthenticationResult + SecurityContext ---

fn make_password_context(principal: PrincipalInfo) -> SecurityContext {
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(principal)
        .build()
        .unwrap();
    SecurityContext::try_from(auth).unwrap()
}

fn make_auth_ctx_with_scope(
    ctx: AuthenticationContext,
    principal: PrincipalInfo,
) -> SecurityContext {
    let auth = AuthenticationResultBuilder::default()
        .context(ctx)
        .principal(principal)
        .build()
        .unwrap();
    SecurityContext::try_from(auth).unwrap()
}

fn make_auth_ctx_with_tr(
    ctx: AuthenticationContext,
    principal: PrincipalInfo,
    tr: TokenRestriction,
) -> SecurityContext {
    let auth = AuthenticationResultBuilder::default()
        .context(ctx)
        .principal(principal)
        .token_restriction(tr)
        .build()
        .unwrap();
    SecurityContext::try_from(auth).unwrap()
}

fn make_auth_result_unscoped(
    principal: PrincipalInfo,
    roles: Option<Vec<RoleRef>>,
) -> SecurityContext {
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(principal)
        .authorization(AuthzInfo {
            scope: ScopeInfo::Unscoped,
            roles,
        })
        .build()
        .unwrap();
    SecurityContext::try_from(auth).unwrap()
}

fn make_auth_result_project(
    principal: PrincipalInfo,
    project: Project,
    roles: Option<Vec<RoleRef>>,
) -> SecurityContext {
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(principal)
        .authorization(AuthzInfo {
            scope: ScopeInfo::Project {
                project,
                project_domain: make_domain(),
            },
            roles,
        })
        .build()
        .unwrap();
    SecurityContext::try_from(auth).unwrap()
}

fn make_auth_result_system(
    principal: PrincipalInfo,
    roles: Option<Vec<RoleRef>>,
) -> SecurityContext {
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(principal)
        .authorization(AuthzInfo {
            scope: ScopeInfo::System("all".into()),
            roles,
        })
        .build()
        .unwrap();
    SecurityContext::try_from(auth).unwrap()
}

fn make_auth_result_domain(
    principal: PrincipalInfo,
    roles: Option<Vec<RoleRef>>,
) -> SecurityContext {
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(principal)
        .authorization(AuthzInfo {
            scope: ScopeInfo::Domain(make_domain()),
            roles,
        })
        .build()
        .unwrap();
    SecurityContext::try_from(auth).unwrap()
}

fn make_trust(trustee_uid: &str) -> Trust {
    TrustBuilder::default()
        .id("trust_id")
        .trustor_user_id("trustor")
        .trustee_user_id(trustee_uid)
        .impersonation(false)
        .build()
        .unwrap()
}

fn make_trust_no_project() -> Trust {
    TrustBuilder::default()
        .id("trust_id")
        .trustor_user_id("trustor")
        .trustee_user_id("trustee")
        .impersonation(false)
        .build()
        .unwrap()
}

fn make_trust_with_roles(roles: Option<Vec<RoleRef>>) -> SecurityContext {
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(make_principal("uid"))
        .authorization(AuthzInfo {
            scope: ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
                trust: make_trust("uid"),
                project: Project {
                    id: "project_id".into(),
                    domain_id: "domain_id".into(),
                    enabled: true,
                    name: "project_name".into(),
                    description: None,
                    is_domain: false,
                    parent_id: None,
                    extra: HashMap::new(),
                },
                project_domain: make_domain(),
            })),
            roles,
        })
        .build()
        .unwrap();
    SecurityContext::try_from(auth).unwrap()
}

fn make_app_cred(user_id: &str) -> ApplicationCredential {
    ApplicationCredentialBuilder::default()
        .id("app_cred_id")
        .name("app_cred_name")
        .project_id("pid")
        .roles(vec![])
        .unrestricted(false)
        .user_id(user_id)
        .build()
        .unwrap()
}

fn make_token_ctx(principal: PrincipalInfo) -> SecurityContext {
    let payload = UnscopedPayloadBuilder::default()
        .user_id(principal.get_user_id())
        .audit_ids(vec!["parent1".to_string(), "parent2".to_string()].into_iter())
        .methods(vec!["password".to_string()].into_iter())
        .expires_at(Utc::now())
        .build()
        .unwrap();
    let token = FernetToken::Unscoped(payload);
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Token(token))
        .principal(principal)
        .build()
        .unwrap();
    SecurityContext::try_from(auth).unwrap()
}

#[test]
fn test_authn_validate_no_user() {
    let authn = UserIdentityInfoBuilder::default()
        .user_id("uid")
        .build()
        .unwrap();
    assert!(authn.validate().is_err());
}

#[test]
fn test_authn_validate_user_disabled() {
    let authn = make_disabled_user("uid");
    if let Err(AuthenticationError::UserDisabled(uid_err)) = authn.validate() {
        assert_eq!("uid", uid_err);
    } else {
        panic!("should fail for disabled user");
    }
}

#[test]
fn test_authn_validate_user_mismatch() {
    let authn = UserIdentityInfoBuilder::default()
        .user_id("uid1")
        .user(make_user("uid2", false))
        .build()
        .unwrap();
    if let Err(AuthenticationError::Unauthorized) = authn.validate() {
    } else {
        panic!("should fail when user_id != user.id");
    }
}

#[test]
fn test_authz_validate_project() {
    assert!(
        ScopeInfo::Project {
            project: make_project(),
            project_domain: make_domain(),
        }
        .validate()
        .is_ok()
    );
}

#[test]
fn test_authz_validate_project_disabled() {
    if let Err(AuthenticationError::ProjectDisabled(..)) = (ScopeInfo::Project {
        project: make_disabled_project(),
        project_domain: make_domain(),
    })
    .validate()
    {
    } else {
        panic!("should fail when project is not enabled");
    }
}

#[test]
fn test_authz_validate_domain() {
    assert!(ScopeInfo::Domain(make_domain()).validate().is_ok());
}

#[test]
fn test_authz_validate_domain_disabled() {
    if let Err(AuthenticationError::DomainDisabled(..)) =
        ScopeInfo::Domain(make_disabled_domain()).validate()
    {
    } else {
        panic!("should fail when domain is not enabled");
    }
}

#[test]
fn test_authz_validate_system() {
    let authz = ScopeInfo::System("system".into());
    assert!(authz.validate().is_ok());
}

#[test]
fn test_authz_validate_unscoped() {
    let authz = ScopeInfo::Unscoped;
    assert!(authz.validate().is_ok());
}

#[test]
fn test_validate_scope_boundaries_with_token_restriction() {
    let s = AllScopes::new();
    let ctx = make_auth_ctx_with_tr(
        AuthenticationContext::Password,
        make_principal("uid"),
        make_token_restriction("pid"),
    );
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.domain),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(ctx.validate_scope_boundaries(&s.project).is_ok());
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.project2),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.trust),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.system),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.unscoped),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
}

#[test]
fn test_validate_scope_boundaries_app_cred() {
    let s = AllScopes::new();
    let ctx = make_auth_ctx_with_scope(
        AuthenticationContext::ApplicationCredential {
            application_credential: ApplicationCredentialBuilder::default()
                .id("app_cred_id")
                .name("app_cred_name")
                .project_id("pid")
                .roles(vec![])
                .unrestricted(false)
                .user_id("uid")
                .build()
                .unwrap(),
            token: None,
        },
        make_principal("uid"),
    );
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.domain),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(ctx.validate_scope_boundaries(&s.project).is_ok());
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.project2),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.trust),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.system),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.unscoped),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
}

#[test]
fn test_validate_scope_boundaries_oidc() {
    let s = AllScopes::new();
    let ctx = make_auth_ctx_with_scope(
        AuthenticationContext::Oidc {
            oidc: OidcContextBuilder::default()
                .idp_id("idp")
                .protocol_id("protocol")
                .build()
                .unwrap(),
            token: None,
        },
        make_principal("uid"),
    );
    assert!(ctx.validate_scope_boundaries(&s.domain).is_ok());
    assert!(ctx.validate_scope_boundaries(&s.project).is_ok());
    assert!(ctx.validate_scope_boundaries(&s.project2).is_ok());
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.trust),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.system),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(ctx.validate_scope_boundaries(&s.unscoped).is_ok());
}

#[test]
fn test_validate_scope_boundarires_k8s() {
    let s = AllScopes::new();
    let tr = make_token_restriction("pid");
    let ctx = make_auth_ctx_with_tr(
        AuthenticationContext::K8s(
            K8sContextBuilder::default()
                .token_restriction_id(tr.id.clone())
                .build()
                .unwrap(),
        ),
        make_principal("uid"),
        tr,
    );
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.domain),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(ctx.validate_scope_boundaries(&s.project).is_ok());
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.project2),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.trust),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.system),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.unscoped),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
}

#[test]
fn test_validate_scope_boundaries_password() {
    let s = AllScopes::new();
    let ctx = make_password_context(make_principal("uid"));
    assert!(ctx.validate_scope_boundaries(&s.domain).is_ok());
    assert!(ctx.validate_scope_boundaries(&s.project).is_ok());
    assert!(ctx.validate_scope_boundaries(&s.project2).is_ok());
    assert!(ctx.validate_scope_boundaries(&s.trust).is_ok());
    assert!(ctx.validate_scope_boundaries(&s.system).is_ok());
    assert!(ctx.validate_scope_boundaries(&s.unscoped).is_ok());
}

#[test]
fn test_validate_scope_boundarires_trust() {
    let p = make_project();
    let p2 = make_project2();
    let d = make_domain();
    let trust = make_trust_with_project(&p.id);
    let trust_scope = ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
        trust: trust.clone(),
        project: p.clone(),
        project_domain: make_domain(),
    }));
    let system = ScopeInfo::System("all".into());
    let unscoped = ScopeInfo::Unscoped;
    let ctx = make_auth_ctx_with_scope(
        AuthenticationContext::Trust { trust, token: None },
        make_principal("uid"),
    );
    assert!(matches!(
        ctx.validate_scope_boundaries(&ScopeInfo::Domain(d)),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    // A plain Project scope for the trust's OWN project is legal (the
    // shape an EC2 credential minted under this trust presents at
    // redemption; roles are still bounded via
    // `calculate_effective_roles()`'s Trust-on-Project handling).
    assert!(
        ctx.validate_scope_boundaries(&ScopeInfo::Project {
            project: p,
            project_domain: make_domain(),
        })
        .is_ok()
    );
    // A different project is still rejected.
    assert!(matches!(
        ctx.validate_scope_boundaries(&ScopeInfo::Project {
            project: p2,
            project_domain: make_domain(),
        }),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(matches!(
        ctx.validate_scope_boundaries(&trust_scope),
        Err(AuthenticationError::Forbidden)
    ));
    assert!(matches!(
        ctx.validate_scope_boundaries(&system),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(matches!(
        ctx.validate_scope_boundaries(&unscoped),
        Err(AuthenticationError::ScopeNotAllowed)
    ));

    // A trust reconstructed from a *presented bearer token* (`token:
    // Some(_)`, the shape produced when decoding an actual trust-scoped
    // Fernet token for reauth/"token" auth method) must NOT be allowed to
    // reach a plain Project scope even for its own project -- a real
    // OS-Trust auth request can only ever request `OS-TRUST:trust` scope,
    // and trust tokens can never be used to mint another token. Only the
    // `token: None` shape (freshly reconstructed, e.g. `/v3/ec2tokens`
    // redemption) may legally reach Project scope, per the assertion
    // above.
    let p3 = make_project();
    let trust2 = make_trust_with_project(&p3.id);
    let bearer_token = FernetToken::Trust(
        TrustPayloadBuilder::default()
            .user_id("uid")
            .methods(["password".to_string()].into_iter())
            .expires_at(Utc::now())
            .trust_id(trust2.id.clone())
            .project_id(p3.id.clone())
            .build()
            .unwrap(),
    );
    let ctx_from_bearer_token = make_auth_ctx_with_scope(
        AuthenticationContext::Trust {
            trust: trust2,
            token: Some(bearer_token),
        },
        make_principal("uid"),
    );
    assert!(matches!(
        ctx_from_bearer_token.validate_scope_boundaries(&ScopeInfo::Project {
            project: p3,
            project_domain: make_domain(),
        }),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
}

#[test]
fn test_validate_scope_boundaries_webauthn() {
    let s = AllScopes::new();
    let ctx = make_auth_ctx_with_scope(AuthenticationContext::WebauthN, make_principal("uid"));
    assert!(ctx.validate_scope_boundaries(&s.domain).is_ok());
    assert!(ctx.validate_scope_boundaries(&s.project).is_ok());
    assert!(ctx.validate_scope_boundaries(&s.project2).is_ok());
    assert!(matches!(
        ctx.validate_scope_boundaries(&s.trust),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(ctx.validate_scope_boundaries(&s.system).is_ok());
    assert!(ctx.validate_scope_boundaries(&s.unscoped).is_ok());
}

#[test]
fn test_fully_resolved_none_authorization() {
    let ctx = make_password_context(make_principal("uid"));
    assert!(matches!(
        ctx.fully_resolved(),
        Err(AuthenticationError::SecurityContextNotResolved)
    ));
}

#[test]
fn test_fully_resolved_unscoped_none_roles() {
    let ctx = make_auth_result_unscoped(make_principal("uid"), None);
    assert!(ctx.fully_resolved().is_ok());
}

#[test]
fn test_fully_resolved_unscoped_empty_roles() {
    let ctx = make_auth_result_unscoped(make_principal("uid"), Some(vec![]));
    assert!(ctx.fully_resolved().is_ok());
}

#[test]
fn test_fully_resolved_scoped_with_roles() {
    let ctx = make_auth_result_project(
        make_principal("uid"),
        make_project(),
        Some(vec![admin_role()]),
    );
    assert!(ctx.fully_resolved().is_ok());
}

#[test]
fn test_fully_resolved_system_with_roles() {
    let ctx = make_auth_result_system(make_principal("uid"), Some(vec![admin_role()]));
    assert!(ctx.fully_resolved().is_ok());
}

#[test]
fn test_fully_resolved_domain_with_roles() {
    let ctx = make_auth_result_domain(make_principal("uid"), Some(vec![admin_role()]));
    assert!(ctx.fully_resolved().is_ok());
}

#[test]
fn test_try_from_auth_to_security_context() {
    let ctx = make_auth_result_project(
        make_principal("uid"),
        make_project(),
        Some(vec![admin_role()]),
    );
    assert!(matches!(
        ctx.authentication_context(),
        AuthenticationContext::Password
    ));
    assert!(matches!(ctx.principal().identity, IdentityInfo::User(_)));
    let authz_scope_match = if let Some(AuthzInfo { scope, .. }) = ctx.authorization()
        && let ScopeInfo::Project { project, .. } = scope
    {
        project.id == "pid"
    } else {
        false
    };
    assert!(authz_scope_match);
}

#[test]
fn test_try_from_auth_unscoped_to_security_context() {
    let ctx = make_auth_result_unscoped(make_principal("uid"), None);
    assert!(matches!(
        ctx.authorization(),
        Some(AuthzInfo {
            scope: ScopeInfo::Unscoped,
            ..
        })
    ));
}

#[test]
fn test_validate_scope_boundaries_system() {
    let s = AllScopes::new();
    let ctx = make_auth_result_system(make_principal("uid"), Some(vec![admin_role()]));
    // Password auth can request any scope
    assert!(ctx.validate_scope_boundaries(&s.project).is_ok());
    assert!(ctx.validate_scope_boundaries(&s.domain).is_ok());
    assert!(ctx.validate_scope_boundaries(&s.system).is_ok());
    assert!(ctx.validate_scope_boundaries(&s.unscoped).is_ok());
}

#[test]
fn test_identity_validate_user() {
    let user = IdentityInfo::User(make_enabled_user("uid"));
    assert!(user.validate().is_ok());
}

#[test]
fn test_identity_validate_user_disabled() {
    let user = IdentityInfo::User(make_disabled_user("uid"));
    if let Err(AuthenticationError::UserDisabled(_)) = user.validate() {
    } else {
        panic!("should fail for disabled user");
    }
}

#[test]
fn test_identity_validate_principal() {
    let principal = IdentityInfo::Principal(
        PrincipalIdentityInfoBuilder::default()
            .id("p1")
            .issuer("https://my.spiffe.id")
            .domain(make_domain())
            .build()
            .unwrap(),
    );
    assert!(principal.validate().is_ok());
}

#[test]
fn test_identity_validate_principal_missing_domain() {
    let principal = IdentityInfo::Principal(
        PrincipalIdentityInfoBuilder::default()
            .id("p1")
            .issuer("https://my.spiffe.id")
            .build()
            .unwrap(),
    );
    assert!(principal.validate().is_ok());
}

#[test]
fn test_identity_validate_principal_disabled_domain() {
    let principal = IdentityInfo::Principal(
        PrincipalIdentityInfoBuilder::default()
            .id("p1")
            .issuer("https://my.spiffe.id")
            .domain(make_disabled_domain())
            .build()
            .unwrap(),
    );
    assert!(matches!(
        principal.validate(),
        Err(AuthenticationError::DomainDisabled(_))
    ));
}

#[test]
fn test_authz_validation_disabled_project() {
    let scope = ScopeInfo::Project {
        project: make_disabled_project(),
        project_domain: make_domain(),
    };
    assert!(matches!(
        scope.validate(),
        Err(AuthenticationError::ProjectDisabled(id)) if id == "pid"
    ));
}

#[test]
fn test_authz_validation_disabled_domain() {
    let scope = ScopeInfo::Domain(make_disabled_domain());
    assert!(matches!(
        scope.validate(),
        Err(AuthenticationError::DomainDisabled(id)) if id == "did"
    ));
}

// --- UserIdentityInfo::validate() user_id length boundary ---

/// A 64-character `user_id` is exactly at the boundary and must be
/// accepted. Distinguishes the `>` length check from a `>=` mutant,
/// which would reject this same input.
#[test]
fn test_user_identity_validate_user_id_64_chars_is_valid() {
    let uid = "a".repeat(64);
    let user = make_enabled_user(&uid);
    assert!(user.validate().is_ok());
}

/// A 65-character `user_id` must be rejected. Distinguishes the `>`
/// length check from a `==` mutant, which would only reject a
/// length of exactly 64.
#[test]
fn test_user_identity_validate_user_id_65_chars_is_invalid() {
    let uid = "a".repeat(65);
    let user = make_enabled_user(&uid);
    assert!(matches!(
        user.validate(),
        Err(AuthenticationError::Validation(_))
    ));
}

/// An empty `user_id` must be rejected. Distinguishes the `||`
/// combining the empty-check and the length-check from an `&&`
/// mutant, under which an empty (and therefore short) `user_id`
/// would never satisfy both sides and would slip through.
#[test]
fn test_user_identity_validate_empty_user_id_is_invalid() {
    let user = make_enabled_user("");
    assert!(matches!(
        user.validate(),
        Err(AuthenticationError::Validation(_))
    ));
}

// --- PrincipalInfo::domain_id() / validate() ---

#[test]
fn test_principal_info_domain_id_reflects_user_domain() {
    let principal = make_principal("uid");
    assert_eq!(principal.domain_id().as_deref(), Some("did"));
}

/// `PrincipalInfo::validate` is a thin delegation to
/// `IdentityInfo::validate`; assert it actually propagates failure
/// rather than only exercising the identity variant directly.
#[test]
fn test_principal_info_validate_propagates_disabled_user() {
    let principal = PrincipalInfo {
        identity: IdentityInfo::User(make_disabled_user("uid")),
    };
    assert!(matches!(
        principal.validate(),
        Err(AuthenticationError::UserDisabled(_))
    ));
}

// --- MFA: TryFrom<Vec<AuthenticationResult>> ---

#[test]
fn test_mfa_principal_mismatch() {
    let auth1 = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(make_principal("uid1"))
        .build()
        .unwrap();
    let auth2 = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(make_principal("uid2"))
        .build()
        .unwrap();
    assert!(matches!(
        SecurityContext::try_from(vec![auth1, auth2]),
        Err(AuthenticationError::AuthnPrincipalMismatch)
    ));
}

#[test]
fn test_mfa_authz_propagated_from_second() {
    let auth1 = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(make_principal("uid"))
        .build()
        .unwrap();
    let auth2 = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(make_principal("uid"))
        .authorization(AuthzInfo {
            scope: ScopeInfo::Unscoped,
            roles: Some(vec![admin_role()]),
        })
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(vec![auth1, auth2]).unwrap();
    assert!(matches!(
        ctx.authorization(),
        Some(AuthzInfo {
            scope: ScopeInfo::Unscoped,
            ..
        })
    ));
    assert!(ctx.authorization().unwrap().roles.is_some());
}

#[test]
fn test_mfa_token_audit_ids_extended() {
    use crate::token::FernetToken;

    let payload1 = UnscopedPayloadBuilder::default()
        .user_id("uid")
        .audit_ids(vec!["parent1".to_string()].into_iter())
        .methods(vec!["token".to_string()].into_iter())
        .expires_at(Utc::now())
        .build()
        .unwrap();
    let token1 = FernetToken::Unscoped(payload1);
    let auth1 = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Token(token1))
        .principal(make_principal("uid"))
        .build()
        .unwrap();

    let payload2 = UnscopedPayloadBuilder::default()
        .user_id("uid")
        .audit_ids(vec!["parent2".to_string(), "parent3".to_string()].into_iter())
        .methods(vec!["token".to_string()].into_iter())
        .expires_at(Utc::now())
        .build()
        .unwrap();
    let token2 = FernetToken::Unscoped(payload2);
    let auth2 = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Token(token2))
        .principal(make_principal("uid"))
        .authorization(AuthzInfo {
            scope: ScopeInfo::Unscoped,
            roles: None,
        })
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(vec![auth1, auth2]).unwrap();
    assert!(ctx.audit_ids().iter().any(|s| s == "parent1"));
    assert!(ctx.audit_ids().iter().any(|s| s == "parent2"));
    assert!(ctx.audit_ids().iter().any(|s| s == "parent3"));
}

#[test]
fn test_mfa_auth_methods_aggregated() {
    let auth1 = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(make_principal("uid"))
        .build()
        .unwrap();
    let _oidc = OidcContextBuilder::default()
        .idp_id("idp")
        .protocol_id("protocol")
        .build()
        .unwrap();
    let auth2 = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Oidc {
            oidc: OidcContextBuilder::default()
                .idp_id("idp")
                .protocol_id("protocol")
                .build()
                .unwrap(),
            token: None,
        })
        .principal(make_principal("uid"))
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(vec![auth1, auth2]).unwrap();
    assert!(ctx.auth_methods().contains("password"));
    assert!(ctx.auth_methods().contains("openid"));
}

#[test]
fn test_mfa_expiry_latest_wins() {
    let base = Utc::now();
    let earlier = base + Duration::hours(1);
    let later = base + Duration::hours(2);
    let auth1 = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(make_principal("uid"))
        .expires_at(earlier)
        .build()
        .unwrap();
    let auth2 = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(make_principal("uid"))
        .expires_at(later)
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(vec![auth1, auth2]).unwrap();
    assert_eq!(ctx.expires_at, Some(later));
}

// --- SecurityContext::validate() principal mismatch arms ---

#[test]
fn test_validate_appcred_principal_mismatch() {
    let appcred = make_app_cred("other_user");
    let ctx = make_auth_ctx_with_scope(
        AuthenticationContext::ApplicationCredential {
            application_credential: appcred,
            token: None,
        },
        make_principal("uid"),
    );
    assert!(matches!(
        ctx.validate(),
        Err(AuthenticationError::AuthzPrincipalMismatch)
    ));
}

#[test]
fn test_validate_appcred_principal_match() {
    let appcred = make_app_cred("uid");
    let ctx = make_auth_ctx_with_scope(
        AuthenticationContext::ApplicationCredential {
            application_credential: appcred,
            token: None,
        },
        make_principal("uid"),
    );
    assert!(ctx.validate().is_ok());
}

#[test]
fn test_validate_trust_principal_mismatch() {
    let trust = make_trust("other_user");
    let ctx = make_auth_ctx_with_scope(
        AuthenticationContext::Trust { trust, token: None },
        make_principal("uid"),
    );
    assert!(matches!(
        ctx.validate(),
        Err(AuthenticationError::AuthzPrincipalMismatch)
    ));
}

#[test]
fn test_validate_trust_principal_match() {
    let trust = make_trust("uid");
    let ctx = make_auth_ctx_with_scope(
        AuthenticationContext::Trust { trust, token: None },
        make_principal("uid"),
    );
    assert!(ctx.validate().is_ok());
}

// --- AuthzInfo::try_set_roles failure path ---

#[test]
fn test_try_set_roles_success() {
    let mut authz = AuthzInfo {
        scope: ScopeInfo::Project {
            project: make_project(),
            project_domain: make_domain(),
        },
        roles: None,
    };
    let assignment = AssignmentBuilder::default()
        .actor_id("uid")
        .role_id("admin")
        .role_name("admin")
        .target_id("pid")
        .r#type(AssignmentType::UserProject)
        .inherited(false)
        .build()
        .unwrap();
    assert!(authz.try_set_roles(vec![assignment]).is_ok());
    assert_eq!(authz.roles.as_ref().unwrap().len(), 1);
    assert_eq!(authz.roles.as_ref().unwrap()[0].id, "admin");
}

// --- HV-08: PrincipalIdentityInfo empty id/issuer ---

#[test]
fn test_principal_empty_id_fails_validate() {
    let principal = PrincipalIdentityInfoBuilder::default()
        .id("")
        .issuer("https://my.spiffe.id")
        .build()
        .unwrap();
    assert!(principal.validate().is_err());
}

#[test]
fn test_principal_empty_issuer_fails_validate() {
    let principal = PrincipalIdentityInfoBuilder::default()
        .id("p1")
        .issuer("")
        .build()
        .unwrap();
    assert!(principal.validate().is_err());
}

// --- Trust scope in fully_resolved() ---

#[test]
fn test_fully_resolved_trust_with_roles() {
    let ctx = make_trust_with_roles(Some(vec![admin_role()]));
    assert!(ctx.fully_resolved().is_ok());
}

// --- FernetToken audit_ids propagation ---

#[test]
fn test_token_ctx_audit_ids_propagated() {
    let ctx = make_token_ctx(make_principal("uid"));
    assert!(ctx.audit_ids().len() >= 3);
    assert!(ctx.audit_ids().iter().any(|s| s == "parent1"));
    assert!(ctx.audit_ids().iter().any(|s| s == "parent2"));
}

#[test]
fn test_token_ctx_methods_include_token() {
    let ctx = make_token_ctx(make_principal("uid"));
    assert!(ctx.auth_methods().contains("password"));
    assert!(ctx.auth_methods().contains("token"));
}

// --- Trust scope ---

#[test]
fn test_trust_no_project_created() {
    let trust = make_trust_no_project();
    assert_eq!(trust.id, "trust_id");
    assert_eq!(trust.trustor_user_id, "trustor");
    assert_eq!(trust.trustee_user_id, "trustee");
}

// --- SecurityContext::is_expired() ---

#[test]
fn test_is_expired_expiry_propagated_from_result() {
    let expires = Utc::now() + Duration::hours(1);
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(make_principal("uid"))
        .expires_at(expires)
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(auth).unwrap();
    assert_eq!(ctx.expires_at, Some(expires));
    assert!(!ctx.is_expired());
}

#[test]
fn test_is_expired_set_after_build() {
    let ctx = SecurityContext::try_from(
        AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_principal("uid"))
            .build()
            .unwrap(),
    )
    .unwrap();
    let mut ctx = ctx;
    ctx.expires_at = Some(Utc::now() - Duration::hours(1));
    assert!(ctx.is_expired());
}

#[test]
fn test_is_expired_no_expiry() {
    let ctx = make_password_context(make_principal("uid"));
    assert_eq!(ctx.expires_at, None);
    assert!(!ctx.is_expired());
}

// --- SecurityContext::expires_at() getter ---

/// Exercises the public `expires_at()` accessor itself (as opposed to
/// the private field), which none of the `is_expired()` tests above
/// do since `is_expired()` reads the field directly.
#[test]
fn test_expires_at_getter_reflects_the_field() {
    let expires = Utc::now() + Duration::hours(1);
    let ctx = SecurityContext::try_from(
        AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_principal("uid"))
            .expires_at(expires)
            .build()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(ctx.expires_at(), Some(expires));
}

// --- SecurityContext::set_token_restriction() ---

#[test]
fn test_set_token_restriction_is_readable_via_getter() {
    let mut ctx = SecurityContext::test_build()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_principal("uid"))
        .build();
    assert!(ctx.token_restriction().is_none());
    ctx.set_token_restriction(make_token_restriction("pid"));
    assert_eq!(
        ctx.token_restriction().map(|tr| tr.project_id.as_deref()),
        Some(Some("pid"))
    );
}

// --- SecurityContext::set_authorization_scope() ---

#[test]
fn test_set_authorization_scope_success() {
    let mut ctx = make_password_context(make_principal("uid"));
    let scope = ScopeInfo::Project {
        project: make_project(),
        project_domain: make_domain(),
    };
    assert!(ctx.set_authorization_scope(scope.clone()).is_ok());
    assert!(matches!(
        ctx.authorization(),
        Some(AuthzInfo {
            scope: ScopeInfo::Project { .. },
            ..
        })
    ));
    assert!(ctx.authorization().unwrap().roles.is_none());
}

#[test]
fn test_set_authorization_scope_preserves_roles() {
    let mut ctx = make_password_context(make_principal("uid"));
    let roles = vec![RoleRef {
        domain_id: None,
        id: "role-a".to_string(),
        name: None,
    }];
    // Pre-set authorization with roles on one scope
    ctx.set_authorization(AuthzInfo {
        roles: Some(roles.clone()),
        scope: ScopeInfo::Unscoped,
    });
    assert!(ctx.authorization().unwrap().roles.is_some());

    // Re-scope to Project — roles should be preserved
    let new_scope = ScopeInfo::Project {
        project: make_project(),
        project_domain: make_domain(),
    };
    assert!(ctx.set_authorization_scope(new_scope).is_ok());
    assert!(matches!(
        ctx.authorization().unwrap().scope,
        ScopeInfo::Project { .. }
    ));
    assert_eq!(
        ctx.authorization().as_ref().and_then(|a| a.roles.as_ref()),
        Some(&roles)
    );
}

#[test]
fn test_set_authorization_scope_fails_restricted_token() {
    let mut ctx = make_auth_ctx_with_tr(
        AuthenticationContext::Password,
        make_principal("uid"),
        make_token_restriction("pid"),
    );
    let scope = ScopeInfo::Domain(make_domain());
    assert!(matches!(
        ctx.set_authorization_scope(scope),
        Err(AuthenticationError::ScopeNotAllowed)
    ));
    assert!(ctx.authorization().is_none());
}

// --- AuthenticationContext::methods() ---

#[test]
fn test_methods_application_credential() {
    let m = AuthenticationContext::ApplicationCredential {
        application_credential: make_app_cred("uid"),
        token: None,
    }
    .methods();
    assert_eq!(
        m,
        HashSet::from_iter(vec!["application_credential".to_string()])
    );
}

#[test]
fn test_methods_oidc() {
    let oidc = OidcContextBuilder::default()
        .idp_id("idp")
        .protocol_id("protocol")
        .build()
        .unwrap();
    let m = AuthenticationContext::Oidc { oidc, token: None }.methods();
    assert_eq!(m, HashSet::from_iter(vec!["openid".to_string()]));
}

#[test]
fn test_methods_k8s() {
    let k8s = K8sContextBuilder::default()
        .token_restriction_id("tr")
        .build()
        .unwrap();
    let m = AuthenticationContext::K8s(k8s).methods();
    assert_eq!(m, HashSet::from_iter(vec!["mapped".to_string()]));
}

#[test]
fn test_methods_password() {
    let m = AuthenticationContext::Password.methods();
    assert_eq!(m, HashSet::from_iter(vec!["password".to_string()]));
}

#[test]
fn test_methods_trust() {
    let trust = make_trust_no_project();
    let m = AuthenticationContext::Trust { trust, token: None }.methods();
    assert_eq!(m, HashSet::from_iter(vec!["trust".to_string()]));
}

#[test]
fn test_methods_webauthn() {
    let m = AuthenticationContext::WebauthN.methods();
    assert_eq!(m, HashSet::from_iter(vec!["x509".to_string()]));
}

#[test]
fn test_methods_token_chain() {
    let payload = UnscopedPayloadBuilder::default()
        .user_id("uid")
        .audit_ids(vec!["parent".to_string()].into_iter())
        .methods(vec!["password".to_string()].into_iter())
        .expires_at(Utc::now())
        .build()
        .unwrap();
    let token = FernetToken::Unscoped(payload);
    let m = AuthenticationContext::Token(token).methods();
    assert!(m.contains("password"));
    assert!(m.contains("token"));
}

// --- PrincipalInfo::get_user_id() Principal variant (UUIDv5) ---

#[test]
fn test_get_user_id_regular_user() {
    let principal = make_principal("uid");
    assert_eq!(principal.get_user_id(), "uid");
}

#[test]
fn test_get_user_id_principal_uuid_v5() {
    let identity = IdentityInfo::Principal(
        PrincipalIdentityInfoBuilder::default()
            .id("spiffe://trust_domain/ns/sa")
            .issuer("https://my.spiffe.id")
            .build()
            .unwrap(),
    );
    let principal = PrincipalInfo { identity };
    let uid = principal.get_user_id();
    let expected = Uuid::new_v5(&NAMESPACE_UUID, b"spiffe://trust_domain/ns/sa")
        .simple()
        .to_string();
    assert_eq!(uid, expected);
}

// --- AuthzInfo::roles() ---

#[test]
fn test_authz_roles_empty() {
    let mut authz = AuthzInfo {
        scope: ScopeInfo::Unscoped,
        roles: None,
    };
    authz.roles(std::iter::empty::<RoleRef>());
    assert!(authz.roles.is_some());
    assert!(authz.roles.as_ref().unwrap().is_empty());
}

#[test]
fn test_authz_roles_multiple() {
    let mut authz = AuthzInfo {
        scope: ScopeInfo::Unscoped,
        roles: None,
    };
    let r1 = RoleRefBuilder::default()
        .id("r1")
        .name("reader")
        .build()
        .unwrap();
    let r2 = RoleRefBuilder::default()
        .id("r2")
        .name("writer")
        .build()
        .unwrap();
    authz.roles(vec![r1, r2].into_iter());
    assert_eq!(authz.roles.as_ref().unwrap().len(), 2);
}

// --- ScopeInfo::validate() for TrustProject ---

#[test]
fn test_authz_validate_trust_project() {
    let scope = ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
        trust: make_trust_no_project(),
        project: make_project(),
        project_domain: make_domain(),
    }));
    assert!(scope.validate().is_ok());
}

#[test]
fn test_authz_validate_trust_project_disabled_project() {
    let scope = ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
        trust: make_trust_no_project(),
        project: make_disabled_project(),
        project_domain: make_domain(),
    }));
    assert!(matches!(
        scope.validate(),
        Err(AuthenticationError::ProjectDisabled(_))
    ));
}

#[test]
fn test_authz_validate_trust_project_disabled_domain() {
    let scope = ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
        trust: make_trust_no_project(),
        project: make_project(),
        project_domain: make_disabled_domain(),
    }));
    assert!(matches!(
        scope.validate(),
        Err(AuthenticationError::DomainDisabled(_))
    ));
}

// --- TryFrom<AuthenticationResult> single conversion ---

#[test]
fn test_try_from_single_auth_result_audit_id() {
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(make_principal("uid"))
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(auth).unwrap();
    assert_eq!(ctx.audit_ids().len(), 1);
    assert!(ctx.auth_methods().contains("password"));
    assert!(matches!(
        ctx.authentication_context(),
        AuthenticationContext::Password
    ));
}

#[test]
fn test_try_from_single_auth_result_token_audit_ids() {
    let payload = UnscopedPayloadBuilder::default()
        .user_id("uid")
        .audit_ids(vec!["parent1".to_string(), "parent2".to_string()].into_iter())
        .methods(vec!["password".to_string()].into_iter())
        .expires_at(Utc::now())
        .build()
        .unwrap();
    let token = FernetToken::Unscoped(payload);
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Token(token))
        .principal(make_principal("uid"))
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(auth).unwrap();
    let has_audit = ctx.audit_ids().iter().any(|s| s == "parent1");
    assert!(has_audit);
    let has_auth = ctx.audit_ids().iter().any(|s| s == "parent2");
    assert!(has_auth);
}

// --- AuthenticationContext::is_delegated (OSSA-2026-015 / ADR 0019 §2) ---

fn make_token_with_methods(methods: Vec<&str>) -> AuthenticationContext {
    let payload = UnscopedPayloadBuilder::default()
        .user_id("uid")
        .audit_ids(std::iter::empty::<String>())
        .methods(methods.into_iter().map(str::to_string))
        .expires_at(Utc::now())
        .build()
        .unwrap();
    AuthenticationContext::Token(FernetToken::Unscoped(payload))
}

#[test]
fn test_is_delegated_direct_application_credential() {
    let ctx = AuthenticationContext::ApplicationCredential {
        application_credential: make_app_cred("uid"),
        token: None,
    };
    assert!(ctx.is_delegated());
}

#[test]
fn test_is_delegated_direct_trust() {
    let ctx = AuthenticationContext::Trust {
        trust: make_trust("uid"),
        token: None,
    };
    assert!(ctx.is_delegated());
}

#[test]
fn test_is_delegated_rescoped_token_carries_trust_method() {
    // matches!(..) is false here (this is a Token variant), so only the
    // methods()-based OR branch can make this true. Catches `||` -> `&&`
    // and matches!-branch deletion mutants.
    let ctx = make_token_with_methods(vec!["trust"]);
    assert!(ctx.is_delegated());
}

#[test]
fn test_is_delegated_rescoped_token_carries_app_cred_method() {
    let ctx = make_token_with_methods(vec!["application_credential"]);
    assert!(ctx.is_delegated());
}

#[test]
fn test_is_delegated_rescoped_token_non_delegated_methods() {
    let ctx = make_token_with_methods(vec!["password", "token"]);
    assert!(!ctx.is_delegated());
}

#[test]
fn test_is_delegated_password_is_false() {
    assert!(!AuthenticationContext::Password.is_delegated());
}

#[test]
fn test_is_delegated_webauthn_is_false() {
    assert!(!AuthenticationContext::WebauthN.is_delegated());
}

// --- ScopeInfo / TrustProjectInfo PartialEq (scope-drift comparisons) ---

fn make_trust_project_info(trust_id: &str, project_id: &str) -> TrustProjectInfo {
    TrustProjectInfo {
        trust: TrustBuilder::default()
            .id(trust_id)
            .trustor_user_id("trustor")
            .trustee_user_id("trustee")
            .impersonation(false)
            .build()
            .unwrap(),
        project: Project {
            id: project_id.into(),
            ..make_project()
        },
        project_domain: make_domain(),
    }
}

#[test]
fn test_scope_info_domain_eq_same_id_and_enabled() {
    assert_eq!(
        ScopeInfo::Domain(make_domain()),
        ScopeInfo::Domain(make_domain())
    );
}

#[test]
fn test_scope_info_domain_eq_different_id_is_false() {
    let other = Domain {
        id: "other_did".into(),
        ..make_domain()
    };
    assert_ne!(ScopeInfo::Domain(make_domain()), ScopeInfo::Domain(other));
}

#[test]
fn test_scope_info_domain_eq_different_enabled_is_false() {
    assert_ne!(
        ScopeInfo::Domain(make_domain()),
        ScopeInfo::Domain(make_disabled_domain())
    );
}

#[test]
fn test_scope_info_project_eq_same_fields() {
    let a = ScopeInfo::Project {
        project: make_project(),
        project_domain: make_domain(),
    };
    let b = ScopeInfo::Project {
        project: make_project(),
        project_domain: make_domain(),
    };
    assert_eq!(a, b);
}

#[test]
fn test_scope_info_project_eq_different_project_id_is_false() {
    let a = ScopeInfo::Project {
        project: make_project(),
        project_domain: make_domain(),
    };
    let b = ScopeInfo::Project {
        project: make_project2(),
        project_domain: make_domain(),
    };
    assert_ne!(a, b);
}

#[test]
fn test_scope_info_project_eq_different_domain_id_is_false() {
    let a = ScopeInfo::Project {
        project: make_project(),
        project_domain: make_domain(),
    };
    let b = ScopeInfo::Project {
        project: Project {
            domain_id: "other_did".into(),
            ..make_project()
        },
        project_domain: make_domain(),
    };
    assert_ne!(a, b);
}

#[test]
fn test_scope_info_project_eq_different_project_enabled_is_false() {
    let a = ScopeInfo::Project {
        project: make_project(),
        project_domain: make_domain(),
    };
    let b = ScopeInfo::Project {
        project: make_disabled_project(),
        project_domain: make_domain(),
    };
    assert_ne!(a, b);
}

#[test]
fn test_scope_info_project_eq_different_project_domain_enabled_is_false() {
    let a = ScopeInfo::Project {
        project: make_project(),
        project_domain: make_domain(),
    };
    let b = ScopeInfo::Project {
        project: make_project(),
        project_domain: make_disabled_domain(),
    };
    assert_ne!(a, b);
}

#[test]
fn test_scope_info_system_eq() {
    assert_eq!(
        ScopeInfo::System("system".into()),
        ScopeInfo::System("system".into())
    );
    assert_ne!(
        ScopeInfo::System("system".into()),
        ScopeInfo::System("other".into())
    );
}

#[test]
fn test_scope_info_trust_project_eq_delegates_to_trust_project_info() {
    let a = ScopeInfo::TrustProject(Box::new(make_trust_project_info("t1", "p1")));
    let b = ScopeInfo::TrustProject(Box::new(make_trust_project_info("t1", "p1")));
    assert_eq!(a, b);

    let c = ScopeInfo::TrustProject(Box::new(make_trust_project_info("t2", "p1")));
    assert_ne!(a, c);
}

#[test]
fn test_scope_info_unscoped_eq() {
    assert_eq!(ScopeInfo::Unscoped, ScopeInfo::Unscoped);
}

#[test]
fn test_scope_info_cross_variant_never_equal() {
    assert_ne!(ScopeInfo::Domain(make_domain()), ScopeInfo::Unscoped);
    assert_ne!(
        ScopeInfo::System("system".into()),
        ScopeInfo::Domain(make_domain())
    );
    assert_ne!(
        ScopeInfo::Project {
            project: make_project(),
            project_domain: make_domain(),
        },
        ScopeInfo::Unscoped
    );
}

#[test]
fn test_trust_project_info_eq_same_ids() {
    assert_eq!(
        make_trust_project_info("t1", "p1"),
        make_trust_project_info("t1", "p1")
    );
}

#[test]
fn test_trust_project_info_eq_different_trust_id_is_false() {
    assert_ne!(
        make_trust_project_info("t1", "p1"),
        make_trust_project_info("t2", "p1")
    );
}

#[test]
fn test_trust_project_info_eq_different_project_id_is_false() {
    assert_ne!(
        make_trust_project_info("t1", "p1"),
        make_trust_project_info("t1", "p2")
    );
}
