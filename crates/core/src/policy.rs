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
//! # Policy enforcement
//!
//! Policy enforcement in Keystone is delegated to the Open Policy Agent. It can
//! be invoked either with the HTTP request or as a WASM module.

use async_trait::async_trait;
use derive_builder::Builder;
#[cfg(any(test, feature = "mock"))]
use mockall::mock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use openstack_keystone_core_types::auth::*;
use openstack_keystone_core_types::trust::Trust;

use crate::auth::ValidatedSecurityContext;
use crate::error::BuilderError;

/// Policy related error.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Module compilation error.
    #[error("module compilation task crashed")]
    Compilation(#[from] eyre::Report),

    /// Dummy policy enforcer cannot be used.
    #[error("dummy (empty) policy enforcer")]
    Dummy,

    /// Forbidden error.
    #[error("{}", .0.violations.as_ref().map(
        |v| v.iter().cloned().map(|x| x.msg)
        .reduce(|acc, s| format!("{acc}, {s}"))
        .unwrap_or_default()
    ).unwrap_or("The request you made requires authentication.".into()))]
    Forbidden(PolicyEvaluationResult),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),

    /// Json serialization error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// The security context must be resolved before the use.
    #[error("security context is not resolved")]
    SecurityContextNotResolved,

    /// A delegated caller's token scope diverged from its own delegation
    /// project. `SecurityContext::validate_scope_boundaries` is supposed to
    /// keep the two pinned equal at all times (OSSA-2026-015); observing a
    /// mismatch here means that invariant did not hold, so the request is
    /// rejected outright rather than handed to the (rego-level) policy
    /// engine, which enforces the same check only per-endpoint. See
    /// `doc/src/security.md` I3.
    #[error("delegated token scope has drifted from its delegation project")]
    ScopeDrift,

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        /// The source of the error.
        #[from]
        source: BuilderError,
    },

    /// Unsupported access scheme.
    #[error("unsupported scheme {0}")]
    UnsupportedScheme(String),

    /// Url parsing error.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
}

#[cfg(feature = "api")]
impl From<PolicyError> for openstack_keystone_api_types::error::KeystoneApiError {
    /// Convert a policy error into a Keystone API error.
    ///
    /// Only a genuine OPA decision (`Forbidden`, meaning the policy engine
    /// ran and denied the request) maps to 403. Every other variant
    /// (transport/serialization failures talking to OPA, an unresolved
    /// security context, a scope-drift invariant violation, ...) is an
    /// internal/plumbing failure, not a policy decision, and must surface
    /// as a 500 -- mapping it to `forbidden` would silently disguise a bug
    /// as an intentional access denial with no server-side error log.
    ///
    /// # Parameters
    /// - `error`: The policy error to convert.
    ///
    /// # Returns
    /// - `Self` - The converted `KeystoneApiError`.
    fn from(error: PolicyError) -> Self {
        if matches!(error, PolicyError::Forbidden(_)) {
            Self::forbidden(error)
        } else {
            Self::internal(error)
        }
    }
}

#[async_trait]
pub trait PolicyEnforcer: Send + Sync {
    /// Enforces a policy for a given action and credentials.
    ///
    /// # Parameters
    /// - `policy_name`: The name of the policy to enforce.
    /// - `credentials`: The credentials of the user requesting the action.
    /// - `target`: The object the action is acting upon (new object for create,
    ///   patch for update, query params for list, `Value::Null` for
    ///   show/delete).
    /// - `existing`: The existing/stored object before the action (for update
    ///   operations), or `None` for create/list/show/delete.
    ///
    /// # Returns
    /// - `Ok(PolicyEvaluationResult)` if the policy was evaluated successfully.
    /// - `Err(PolicyError)` if an error occurred during enforcement.
    async fn enforce(
        &self,
        policy_name: &'static str,
        credentials: &ValidatedSecurityContext,
        target: Value,
        existing: Option<Value>,
    ) -> Result<PolicyEvaluationResult, PolicyError>;

    /// Performs a health check of the policy enforcer.
    ///
    /// # Returns
    /// - `Ok(())` if the enforcer is healthy.
    /// - `Err(PolicyError)` if the enforcer is unhealthy.
    async fn health_check(&self) -> Result<(), PolicyError> {
        Ok(())
    }
}

//#[async_trait]
//pub trait PolicyEnforcerExt: Send + Sync {
//    /// Enforces a policy for a given action and credentials.
//    ///
//    /// # Parameters
//    /// - `policy_name`: The name of the policy to enforce.
//    /// - `credentials`: The credentials of the user requesting the action.
//    /// - `target`: The target resource of the action.
//    /// - `update`: Optional update data for the resource.
//    ///
//    /// # Returns
//    /// - `Ok(PolicyEvaluationResult)` if the policy was evaluated
// successfully.    /// - `Err(PolicyError)` if an error occurred during
// enforcement.    async fn enforce<C: Into<Credentials>>(
//        &self,
//        policy_name: &'static str,
//        credentials: &C,
//        target: Value,
//        update: Option<Value>,
//    ) -> Result<PolicyEvaluationResult, PolicyError>;
//}

#[cfg(any(test, feature = "mock"))]
mock! {
    pub Policy {}

    #[async_trait]
    impl PolicyEnforcer for Policy {
        async fn enforce(
            &self,
            policy_name: &'static str,
            credentials: &ValidatedSecurityContext,
            target: Value,
            existing: Option<Value>
        ) -> Result<PolicyEvaluationResult, PolicyError>;

        async fn health_check(&self) -> Result<(), PolicyError>;
    }
}

#[derive(Debug, Error)]
#[error("failed to evaluate policy")]
pub enum EvaluationError {
    Serialization(#[from] serde_json::Error),
    Evaluation(#[from] eyre::Report),
}

/// OpenPolicyAgent `Credentials` object.
#[derive(Builder, Serialize, Debug)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct Credentials {
    /// Specifies whether the user is an admin.
    pub is_admin: bool,

    /// User ID.
    pub user_id: String,

    /// List of roles the principal has on the scope.
    #[builder(default)]
    #[serde(default, rename(serialize = "roles"))]
    pub roles: Vec<String>,

    // TODO: replace scope info with a flattened enum
    #[builder(default)]
    #[serde(default)]
    pub project_id: Option<String>,

    #[builder(default)]
    #[serde(default)]
    pub domain_id: Option<String>,

    /// The domain of the currently-scoped project, when the caller holds a
    /// project (or trust-project) scoped token. Distinct from `domain_id`
    /// (which is only set for a genuinely *domain*-scoped token) so that
    /// policies gating on domain-scope membership (e.g. the `manager` role
    /// checks in `domain_matches_domain_scope`) cannot be satisfied merely
    /// by holding a role on a project that happens to live in that domain.
    /// `None` for domain/system/unscoped tokens.
    #[builder(default)]
    #[serde(default)]
    pub project_domain_id: Option<String>,

    /// System scope information.
    #[builder(default)]
    #[serde(default)]
    pub system: Option<String>,

    #[builder(default)]
    #[serde(default)]
    pub trust: Option<Trust>,

    /// Canonical auth-method string for this request (e.g. `"password"`,
    /// `"token"`, `"trust"`, `"application_credential"`), from
    /// [`AuthenticationContext::auth_type`]. See [`Self::is_delegated`]
    /// for the derived, rescope-aware delegation flag `.rego` rules
    /// should actually gate on.
    pub auth_type: String,

    /// Whether this request is authenticated via a delegated credential
    /// (trust or application credential), directly or carried forward
    /// through a re-scoped token — [`AuthenticationContext::is_delegated`].
    ///
    /// # Security Note
    ///
    /// Delegated tokens must remain bounded to their delegation
    /// `project_id` (OSSA-2026-015 / ADR 0019 §2). Policies that grant
    /// access based on `user_id` ownership alone must additionally check
    /// this flag together with `project_id` before allowing a delegated
    /// caller to reach a resource.
    pub is_delegated: bool,

    /// For application-credential authentication only: whether the
    /// application credential is `unrestricted` (may be used for
    /// management operations such as creating other application
    /// credentials, trusts, or EC2 credentials). `None` for every other
    /// authentication method.
    ///
    /// # Security Note
    ///
    /// A *restricted* application credential (`unrestricted == false`)
    /// must not be usable to create new credentials that outlive or
    /// escape its own limited role set (OSSA-2026-005 / CVE-2026-33551).
    #[builder(default)]
    #[serde(default)]
    pub unrestricted: Option<bool>,

    /// The immutable project the active delegation (trust or application
    /// credential) is bound to, taken from the authentication chain held
    /// in [`ValidatedSecurityContext`] rather than from the request's
    /// token scope. `None` for non-delegated authentication.
    ///
    /// # Security Note
    ///
    /// Delegation boundary checks (OSSA-2026-015) must anchor on this
    /// chain-derived value, **not** on [`Self::project_id`] (the token
    /// scope), so that a scope rebind can never move a delegated caller's
    /// boundary. Policies should additionally assert `project_id ==
    /// delegated_project_id` for delegated callers as a scope-drift
    /// tripwire — the two are pinned equal at token-issuance time
    /// ([`SecurityContext::validate_scope_boundaries`]), so any divergence
    /// signals a compromised or malformed context and must fail closed.
    #[builder(default)]
    #[serde(default)]
    pub delegated_project_id: Option<String>,

    /// Extra claims a `mode = full_auth` dynamic auth plugin (ADR 0025)
    /// attached to its `authenticate` response, outer-keyed by
    /// `plugin_name` so `.rego` rules index as
    /// `input.credentials.plugin_claims.<plugin_name>.<key>` - never
    /// flattened to the top level, so a plugin-supplied key can never
    /// collide with or shadow a privilege-relevant field above (ADR §7
    /// "Response Payload Bounds"). `None`/absent for every other
    /// authentication method, and for a `WasmPlugin` authentication whose
    /// response carried no claims.
    #[builder(default)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_claims:
        Option<std::collections::HashMap<String, std::collections::HashMap<String, Value>>>,
}

impl TryFrom<&ValidatedSecurityContext> for Credentials {
    type Error = PolicyError;
    /// Convert a token into credentials for policy evaluation.
    ///
    /// # Parameters
    /// - `token`: The token to convert.
    ///
    /// # Returns
    /// - `Self` - The constructed `Credentials` object.
    fn try_from(sc: &ValidatedSecurityContext) -> Result<Self, Self::Error> {
        let mut builder = CredentialsBuilder::default();
        builder.user_id(sc.principal().get_user_id());
        builder.is_admin(sc.is_admin());
        builder.auth_type(sc.authentication_context().auth_type());
        builder.is_delegated(sc.authentication_context().is_delegated());
        // Delegation facts are taken from the authentication chain, not the
        // token scope, so the policy engine sees the delegation's own
        // immutable binding (OSSA-2026-015). See `delegated_project_id`.
        match sc.authentication_context() {
            AuthenticationContext::ApplicationCredential {
                application_credential,
                ..
            } => {
                builder.unrestricted(application_credential.unrestricted);
                builder.delegated_project_id(application_credential.project_id.clone());
            }
            AuthenticationContext::Trust { trust, .. } => {
                if let Some(project_id) = &trust.project_id {
                    builder.delegated_project_id(project_id.clone());
                }
                builder.trust(trust.clone());
            }
            AuthenticationContext::WasmPlugin {
                plugin_name,
                claims,
                ..
            } if !claims.is_empty() => {
                builder.plugin_claims(std::collections::HashMap::from([(
                    plugin_name.clone(),
                    claims.clone(),
                )]));
            }
            // Not delegated (or, for WasmPlugin, delegated but carrying no
            // claims) -- nothing extra to project. Named explicitly, not a
            // wildcard, so a new AuthenticationContext variant is a compile
            // error here until a human decides how it fits (security.md
            // V2 / Gate J, issue #986).
            AuthenticationContext::WasmPlugin { .. }
            | AuthenticationContext::Oidc { .. }
            | AuthenticationContext::K8s(_)
            | AuthenticationContext::Password
            | AuthenticationContext::Admin
            | AuthenticationContext::Token(_)
            | AuthenticationContext::WebauthN
            | AuthenticationContext::Mapping(_)
            | AuthenticationContext::Ec2Credential
            | AuthenticationContext::Totp => {}
        }
        if let Some(authz) = sc.authorization() {
            match &authz.scope {
                ScopeInfo::Domain(domain) => {
                    builder.domain_id(domain.id.clone());
                }
                ScopeInfo::Project {
                    project,
                    project_domain,
                } => {
                    builder.project_id(project.id.clone());
                    builder.project_domain_id(project_domain.id.clone());
                }
                ScopeInfo::System(system) => {
                    if system == "system" {
                        builder.system("all");
                    } else {
                        builder.system(system.clone());
                    }
                }
                ScopeInfo::TrustProject(tpi) => {
                    builder.project_id(tpi.project.id.clone());
                    builder.project_domain_id(tpi.project_domain.id.clone());
                    builder.trust(tpi.trust.clone());
                }
                ScopeInfo::Unscoped => {}
            }
            if !matches!(authz.scope, ScopeInfo::Unscoped) {
                if let Some(roles) = &authz.effective_roles() {
                    builder.roles(
                        roles
                            .iter()
                            .filter_map(|role| role.name.clone())
                            .collect::<Vec<_>>(),
                    );
                } else {
                    return Err(PolicyError::SecurityContextNotResolved);
                }
            }
        }
        let cred = builder.build()?;
        // Rust-side scope-drift tripwire (I3): mirrors the check every
        // delegated .rego policy carries individually, but here it covers
        // *every* caller of `Credentials::try_from`, including any future
        // policy that forgets to copy the rego-level assertion.
        // `validate_scope_boundaries` is supposed to keep a delegated
        // caller's scope pinned to its delegation project, so any observed
        // divergence means that upstream invariant broke -- fail closed
        // rather than trust the (already-suspect) request further.
        if let Some(delegated_project_id) = &cred.delegated_project_id
            && let Some(project_id) = &cred.project_id
            && project_id != delegated_project_id
        {
            return Err(PolicyError::ScopeDrift);
        }
        Ok(cred)
    }
}

/// A single violation of a policy.
#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct Violation {
    pub msg: String,
    pub field: Option<String>,
}

/// The OpenPolicyAgent response.
#[derive(Deserialize, Debug)]
pub struct OpaResponse {
    pub result: PolicyEvaluationResult,
}

/// The result of a policy evaluation.
#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct PolicyEvaluationResult {
    /// Whether the user is allowed to perform the request or not.
    pub allow: bool,
    /// Whether the user is allowed to see resources of other domains.
    #[serde(default)]
    pub can_see_other_domain_resources: Option<bool>,
    /// List of violations.
    #[serde(rename = "violation")]
    pub violations: Option<Vec<Violation>>,
}

impl std::fmt::Display for PolicyEvaluationResult {
    /// Format the policy evaluation result as a string.
    ///
    /// # Parameters
    /// - `f`: The formatter to use.
    ///
    /// # Returns
    /// - `std::fmt::Result` - The result of the formatting operation.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        if let Some(violations) = &self.violations {
            for violation in violations {
                if first {
                    first = false;
                } else {
                    write!(f, ", ")?;
                }
                write!(f, "{}", violation.msg)?;
            }
        }
        Ok(())
    }
}

impl PolicyEvaluationResult {
    /// Returns whether the request is allowed.
    ///
    /// # Returns
    /// - `bool` - True if allowed, false otherwise.
    #[must_use]
    pub fn allow(&self) -> bool {
        self.allow
    }

    /// Returns true if the policy evaluation was successful.
    ///
    /// # Returns
    /// - `bool` - True if valid, false otherwise.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.violations
            .as_deref()
            .map(|x| x.is_empty())
            .unwrap_or(false)
    }

    /// Create an allowed evaluation result.
    ///
    /// # Returns
    /// - `Self` - A result indicating the request is allowed.
    #[cfg(any(test, feature = "mock"))]
    pub fn allowed() -> Self {
        Self {
            allow: true,
            can_see_other_domain_resources: None,
            violations: None,
        }
    }

    /// Create an allowed admin evaluation result.
    ///
    /// # Returns
    /// - `Self` - A result indicating the request is allowed for admins.
    #[cfg(any(test, feature = "mock"))]
    pub fn allowed_admin() -> Self {
        Self {
            allow: true,
            can_see_other_domain_resources: Some(true),
            violations: None,
        }
    }

    /// Create a forbidden evaluation result.
    ///
    /// # Returns
    /// - `Self` - A result indicating the request is forbidden.
    #[cfg(any(test, feature = "mock"))]
    pub fn forbidden() -> Self {
        Self {
            allow: false,
            can_see_other_domain_resources: Some(false),
            violations: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::policy_contract;
    use crate::api::tests::test_fixture_scoped;
    use openstack_keystone_core_types::role::RoleRef;

    /// A project-scoped token must carry the domain of the scoped project
    /// as `project_domain_id`, distinct from `domain_id` (which stays
    /// unset for project scope) so policies like
    /// `identity/resource/domain/show` can grant a project-scoped caller
    /// read access to their own domain without conflating it with genuine
    /// domain-scope membership (`domain_matches_domain_scope`).
    #[test]
    fn credentials_from_project_scope_carries_project_domain_id() {
        let vsc = test_fixture_scoped();
        let creds = Credentials::try_from(&vsc).unwrap();
        assert_eq!(creds.project_id.as_deref(), Some("project_id"));
        assert_eq!(creds.project_domain_id.as_deref(), Some("domain_id"));
        assert_eq!(creds.domain_id, None);
    }

    #[test]
    fn credentials_from_domain_scope_leaves_project_domain_id_unset() {
        let authz = AuthzInfoBuilder::default()
            .roles(vec![RoleRef {
                id: "admin".to_string(),
                name: Some("admin".to_string()),
                domain_id: None,
            }])
            .scope(ScopeInfo::Domain(
                openstack_keystone_core_types::resource::Domain {
                    id: "domain_id".to_string(),
                    name: "domain_name".to_string(),
                    enabled: true,
                    ..Default::default()
                },
            ))
            .build()
            .unwrap();

        let user = openstack_keystone_core_types::identity::UserResponseBuilder::default()
            .id("uid")
            .domain_id("domain_id")
            .enabled(true)
            .name("testuser")
            .build()
            .unwrap();

        let sc = SecurityContext::test_build()
            .authentication_context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .user(user)
                        .user_domain(openstack_keystone_core_types::resource::Domain {
                            id: "domain_id".to_string(),
                            name: "domain_name".to_string(),
                            enabled: true,
                            ..Default::default()
                        })
                        .build()
                        .unwrap(),
                ),
            })
            .authorization(authz)
            .build();

        let vsc = ValidatedSecurityContext::test_new(sc);
        let creds = Credentials::try_from(&vsc).unwrap();
        assert_eq!(creds.domain_id.as_deref(), Some("domain_id"));
        assert_eq!(creds.project_domain_id, None);
        assert_eq!(creds.project_id, None);
    }

    /// Gate I (security review V9, issue #987): a structural test that
    /// `Credentials` -- the auth-chain projection sent to OPA on every
    /// request -- never serializes a secret-bearing field, regardless of
    /// which fields are populated. Currently vacuous (no field on
    /// `Credentials` carries decrypted secret material today), but that is
    /// exactly the point: it exists to catch a *future* field addition
    /// that reintroduces one, the way `credential_policy_input`'s `blob`
    /// stripping guards the sibling `target`/`existing` half of the
    /// policy-input document (Gate B2).
    #[test]
    fn test_credentials_serialization_never_leaks_secrets() {
        let creds = CredentialsBuilder::default()
            .is_admin(false)
            .user_id("uid")
            .roles(vec!["member".to_string()])
            .project_id("pid".to_string())
            .auth_type("trust")
            .is_delegated(true)
            .unrestricted(false)
            .delegated_project_id("pid".to_string())
            .trust(Trust {
                id: "t1".to_string(),
                trustor_user_id: "trustor".to_string(),
                trustee_user_id: "trustee".to_string(),
                impersonation: false,
                project_id: Some("pid".to_string()),
                expires_at: None,
                deleted_at: None,
                extra: None,
                remaining_uses: None,
                redelegated_trust_id: None,
                redelegation_count: None,
                roles: Some(vec![]),
            })
            .plugin_claims(std::collections::HashMap::from([(
                "acme_sso".to_string(),
                std::collections::HashMap::from([(
                    "department".to_string(),
                    serde_json::json!("engineering"),
                )]),
            )]))
            .build()
            .unwrap();

        let value = serde_json::to_value(&creds).unwrap();
        policy_contract::assert_no_secrets(&value);
    }

    fn vsc_with_ctx_and_project(
        auth_ctx: AuthenticationContext,
        project_id: &str,
    ) -> ValidatedSecurityContext {
        let user = openstack_keystone_core_types::identity::UserResponseBuilder::default()
            .id("uid")
            .domain_id("domain_id")
            .enabled(true)
            .name("testuser")
            .build()
            .unwrap();
        let authz = AuthzInfoBuilder::default()
            .roles(vec![RoleRef {
                id: "admin".to_string(),
                name: Some("admin".to_string()),
                domain_id: None,
            }])
            .scope(ScopeInfo::Project {
                project: openstack_keystone_core_types::resource::Project {
                    id: project_id.to_string(),
                    domain_id: "domain_id".to_string(),
                    enabled: true,
                    name: "proj".to_string(),
                    ..Default::default()
                },
                project_domain: openstack_keystone_core_types::resource::Domain {
                    id: "domain_id".to_string(),
                    name: "domain_name".to_string(),
                    enabled: true,
                    ..Default::default()
                },
            })
            .build()
            .unwrap();
        let sc = SecurityContext::test_build()
            .authentication_context(auth_ctx)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .user(user)
                        .user_domain(openstack_keystone_core_types::resource::Domain {
                            id: "domain_id".to_string(),
                            name: "domain_name".to_string(),
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

    fn make_ac(
        project_id: &str,
        unrestricted: bool,
    ) -> openstack_keystone_core_types::application_credential::ApplicationCredential {
        openstack_keystone_core_types::application_credential::ApplicationCredential {
            id: "ac1".to_string(),
            user_id: "uid".to_string(),
            project_id: project_id.to_string(),
            name: "cred".to_string(),
            description: None,
            roles: vec![],
            unrestricted,
            expires_at: None,
            access_rules: None,
        }
    }

    fn make_trust_ctx(project_id: Option<&str>) -> Trust {
        Trust {
            id: "t1".to_string(),
            trustor_user_id: "trustor".to_string(),
            trustee_user_id: "uid".to_string(),
            impersonation: false,
            project_id: project_id.map(|s| s.to_string()),
            expires_at: None,
            deleted_at: None,
            extra: None,
            remaining_uses: None,
            redelegated_trust_id: None,
            redelegation_count: None,
            roles: Some(vec![]),
        }
    }

    /// Application-credential delegation facts (project + unrestricted flag)
    /// must land on `Credentials` from the auth chain. Catches deletion of
    /// the `ApplicationCredential` match arm in
    /// `TryFrom<&ValidatedSecurityContext>`.
    #[test]
    fn credentials_from_application_credential_carries_delegation_facts() {
        let vsc = vsc_with_ctx_and_project(
            AuthenticationContext::ApplicationCredential {
                application_credential: make_ac("project_id", true),
                token: None,
            },
            "project_id",
        );
        let creds = Credentials::try_from(&vsc).unwrap();
        assert_eq!(creds.delegated_project_id.as_deref(), Some("project_id"));
        assert_eq!(creds.unrestricted, Some(true));
        assert!(creds.is_delegated);
    }

    /// Trust delegation facts (project + trust object) must land on
    /// `Credentials`. Catches deletion of the `Trust` match arm.
    #[test]
    fn credentials_from_trust_carries_delegation_facts() {
        let vsc = vsc_with_ctx_and_project(
            AuthenticationContext::Trust {
                trust: make_trust_ctx(Some("project_id")),
                token: None,
            },
            "project_id",
        );
        let creds = Credentials::try_from(&vsc).unwrap();
        assert_eq!(creds.delegated_project_id.as_deref(), Some("project_id"));
        assert!(creds.trust.is_some());
        assert!(creds.is_delegated);
    }

    /// A trust with no bound project must not fabricate a
    /// `delegated_project_id`.
    #[test]
    fn credentials_from_trust_without_project_leaves_delegated_project_id_unset() {
        let vsc = vsc_with_ctx_and_project(
            AuthenticationContext::Trust {
                trust: make_trust_ctx(None),
                token: None,
            },
            "project_id",
        );
        let creds = Credentials::try_from(&vsc).unwrap();
        assert_eq!(creds.delegated_project_id, None);
    }

    /// Non-delegated auth methods must not populate `unrestricted` or
    /// `delegated_project_id`.
    #[test]
    fn credentials_from_password_has_no_delegation_facts() {
        let vsc = vsc_with_ctx_and_project(AuthenticationContext::Password, "project_id");
        let creds = Credentials::try_from(&vsc).unwrap();
        assert_eq!(creds.delegated_project_id, None);
        assert_eq!(creds.unrestricted, None);
        assert!(!creds.is_delegated);
    }

    /// The system-scope alias: the literal `"system"` scope value must map
    /// to `"all"`, while any other named system scope passes through
    /// unchanged. Catches `==` -> `!=` on the alias check.
    #[test]
    fn credentials_system_scope_all_alias() {
        let authz = AuthzInfoBuilder::default()
            .roles(vec![])
            .scope(ScopeInfo::System("system".to_string()))
            .build()
            .unwrap();
        let sc = SecurityContext::test_build()
            .authentication_context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .user(
                            openstack_keystone_core_types::identity::UserResponseBuilder::default()
                                .id("uid")
                                .domain_id("domain_id")
                                .enabled(true)
                                .name("testuser")
                                .build()
                                .unwrap(),
                        )
                        .user_domain(openstack_keystone_core_types::resource::Domain {
                            id: "domain_id".to_string(),
                            name: "domain_name".to_string(),
                            enabled: true,
                            ..Default::default()
                        })
                        .build()
                        .unwrap(),
                ),
            })
            .authorization(authz)
            .build();
        let vsc = ValidatedSecurityContext::test_new(sc);
        let creds = Credentials::try_from(&vsc).unwrap();
        assert_eq!(creds.system.as_deref(), Some("all"));
    }

    #[test]
    fn credentials_system_scope_named_passes_through() {
        let authz = AuthzInfoBuilder::default()
            .roles(vec![])
            .scope(ScopeInfo::System("other_system".to_string()))
            .build()
            .unwrap();
        let sc = SecurityContext::test_build()
            .authentication_context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .user(
                            openstack_keystone_core_types::identity::UserResponseBuilder::default()
                                .id("uid")
                                .domain_id("domain_id")
                                .enabled(true)
                                .name("testuser")
                                .build()
                                .unwrap(),
                        )
                        .user_domain(openstack_keystone_core_types::resource::Domain {
                            id: "domain_id".to_string(),
                            name: "domain_name".to_string(),
                            enabled: true,
                            ..Default::default()
                        })
                        .build()
                        .unwrap(),
                ),
            })
            .authorization(authz)
            .build();
        let vsc = ValidatedSecurityContext::test_new(sc);
        let creds = Credentials::try_from(&vsc).unwrap();
        assert_eq!(creds.system.as_deref(), Some("other_system"));
    }

    /// A `WasmPlugin` context with claims must project them into
    /// `plugin_claims`, keyed by plugin name. Catches the `!claims.is_empty()`
    /// guard being flipped or deleted.
    #[test]
    fn credentials_from_wasm_plugin_with_claims_populates_plugin_claims() {
        let mut claims = std::collections::HashMap::new();
        claims.insert("department".to_string(), serde_json::json!("engineering"));
        let vsc = vsc_with_ctx_and_project(
            AuthenticationContext::WasmPlugin {
                plugin_name: "acme_sso".to_string(),
                claims,
                token: None,
            },
            "project_id",
        );
        let creds = Credentials::try_from(&vsc).unwrap();
        let plugin_claims = creds.plugin_claims.expect("plugin_claims must be set");
        assert!(plugin_claims.contains_key("acme_sso"));
    }

    /// A `WasmPlugin` context with no claims must leave `plugin_claims`
    /// unset (not an empty map keyed by plugin name).
    #[test]
    fn credentials_from_wasm_plugin_without_claims_leaves_plugin_claims_unset() {
        let vsc = vsc_with_ctx_and_project(
            AuthenticationContext::WasmPlugin {
                plugin_name: "acme_sso".to_string(),
                claims: std::collections::HashMap::new(),
                token: None,
            },
            "project_id",
        );
        let creds = Credentials::try_from(&vsc).unwrap();
        assert_eq!(creds.plugin_claims, None);
    }

    /// Scope-drift tripwire (I3): a delegated caller whose token scope no
    /// longer matches its delegation project must fail closed with
    /// `ScopeDrift`, never silently succeed. Catches `!=` -> `==` on the
    /// drift comparison.
    #[test]
    fn credentials_scope_drift_between_token_and_delegation_project_is_rejected() {
        let vsc = vsc_with_ctx_and_project(
            AuthenticationContext::ApplicationCredential {
                application_credential: make_ac("delegation_project", false),
                token: None,
            },
            "other_project",
        );
        let err = Credentials::try_from(&vsc).unwrap_err();
        assert!(matches!(err, PolicyError::ScopeDrift));
    }

    /// Same delegation and token project: no drift, succeeds normally.
    #[test]
    fn credentials_no_scope_drift_when_projects_match() {
        let vsc = vsc_with_ctx_and_project(
            AuthenticationContext::ApplicationCredential {
                application_credential: make_ac("project_id", false),
                token: None,
            },
            "project_id",
        );
        assert!(Credentials::try_from(&vsc).is_ok());
    }
}
