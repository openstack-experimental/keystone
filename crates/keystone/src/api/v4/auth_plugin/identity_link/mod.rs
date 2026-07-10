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
//! Admin-authorized external identity linking (ADR 0025 §4). An admin pairs
//! a pre-existing Keystone `user_id` with the `external_id` a `full_auth`
//! plugin's `find_user` resolves - the one path by which such a plugin can
//! authenticate a user it did not itself provision, gated by ordinary RBAC
//! rather than the plugin's own runtime logic.

use openstack_keystone_config::{DynamicPluginConfig, PluginMode};
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::assignment::{AssignmentType, RoleAssignmentListParameters};

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

pub mod create;
pub mod delete;

/// True if `domain_id` is one the plugin was configured to reach
/// (`provision_domain_id` or a member of `allowed_provision_domains`, ADR
/// §6.B). A link can never place a user outside that set, keeping the domain
/// invariant uniform whether an identity arrived via self-provisioning or
/// admin-linking.
fn domain_allowed(config: &DynamicPluginConfig, domain_id: &str) -> bool {
    config.provision_domain_id.as_deref() == Some(domain_id)
        || config
            .allowed_provision_domains
            .iter()
            .any(|d| d == domain_id)
}

/// Load the `[auth_plugin.<name>]` config, rejecting a plugin that is not
/// installed or is not `full_auth` - `mapping`/`route` plugins never call
/// `find_user`, so an identity link for them is meaningless (ADR §4).
pub(super) async fn require_full_auth_plugin(
    state: &ServiceState,
    plugin_name: &str,
) -> Result<DynamicPluginConfig, KeystoneApiError> {
    let config = {
        let cfg = state.config_manager.config.read().await;
        cfg.auth_plugin.get(plugin_name).cloned()
    };
    let config = config.ok_or_else(|| KeystoneApiError::NotFound {
        resource: "auth_plugin".to_string(),
        identifier: plugin_name.to_string(),
    })?;
    if config.mode != PluginMode::FullAuth {
        return Err(KeystoneApiError::BadRequest(format!(
            "plugin {plugin_name} is not a full_auth plugin; identity links apply only to full_auth mode"
        )));
    }
    Ok(config)
}

/// Whether `user_id` holds any system-scope role assignment (directly or via
/// a group). Drives RBAC tiering in policy: linking a principal that can
/// reach system scope requires system-admin authorization, not just
/// domain-admin (ADR §4, mirroring ADR 0020 §9.A).
async fn target_holds_system_role(
    state: &ServiceState,
    exec: &ExecutionContext<'_>,
    user_id: &str,
) -> Result<bool, KeystoneApiError> {
    let params = RoleAssignmentListParameters {
        user_id: Some(user_id.to_string()),
        effective: Some(true),
        ..Default::default()
    };
    let assignments = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(exec, &params)
        .await?;
    Ok(assignments.iter().any(|a| {
        matches!(
            a.r#type,
            AssignmentType::UserSystem | AssignmentType::GroupSystem
        )
    }))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use sea_orm::DatabaseConnection;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_api_types::v4::auth_plugin::{
        IdentityLinkCreate, IdentityLinkCreateRequest, IdentityLinkResponse, RevokeAllResponse,
    };
    use openstack_keystone_audit::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager, DynamicPluginConfig, PluginMode};
    use openstack_keystone_core::api::tests::test_fixture_scoped;
    use openstack_keystone_core_types::identity::{UserResponse, UserResponseBuilder};
    use openstack_keystone_core_types::revoke::RevocationEvent;

    use crate::assignment::MockAssignmentProvider;
    use crate::auth_plugin_identity::MockDynamicPluginIdentityProvider;
    use crate::identity::MockIdentityProvider;
    use crate::keystone::{Service, ServiceState};
    use crate::policy::{MockPolicy, PolicyError, PolicyEvaluationResult};
    use crate::provider::Provider;
    use crate::revoke::MockRevokeProvider;

    use super::super::openapi_router;

    const PLUGIN: &str = "tf_appcred_handler";
    // Matches the domain of the principal `test_fixture_scoped` mints.
    const DOMAIN: &str = "domain_id";

    /// Non-essential fields at their documented defaults
    /// (`crates/config/src/auth_plugins.rs`); the linking handler only
    /// reads `mode`/`provision_domain_id`, never loads the wasm, so `path`
    /// and `sha256` are dummies.
    fn plugin_config(mode: PluginMode, provision_domain_id: Option<&str>) -> DynamicPluginConfig {
        DynamicPluginConfig {
            path: PathBuf::from("/nonexistent.wasm"),
            sha256: "00".to_string(),
            mode,
            capabilities: Vec::new(),
            exposed_headers: Vec::new(),
            allowed_hosts: Vec::new(),
            http_fetch_follow_redirects: false,
            http_fetch_auth_header: None,
            http_fetch_auth_secret_env: None,
            provision_domain_id: provision_domain_id.map(str::to_string),
            allowed_provision_domains: Vec::new(),
            assign_role_allowed: Vec::new(),
            inspect_methods: Vec::new(),
            route_targets: Vec::new(),
            timeout_ms: 1_000,
            fuel_limit: 10_000_000,
            memory_limit_mb: 16,
            invocation_rate_limit_per_source_per_minute: 20,
            invocation_rate_limit_per_minute: 300,
            max_concurrent_invocations: 16,
            valid_since: None,
        }
    }

    fn config_with(plugin: Option<DynamicPluginConfig>) -> Config {
        let auth_plugin = plugin
            .into_iter()
            .map(|c| (PLUGIN.to_string(), c))
            .collect();
        Config {
            auth_plugin,
            ..Default::default()
        }
    }

    fn user_response(domain_id: &str) -> UserResponse {
        UserResponseBuilder::default()
            .id("target-user")
            .domain_id(domain_id.to_string())
            .name("linked")
            .enabled(true)
            .build()
            .unwrap()
    }

    fn mock_policy(allow: bool) -> MockPolicy {
        let mut policy = MockPolicy::default();
        policy.expect_enforce().returning(move |_, _, _, _| {
            if allow {
                Ok(PolicyEvaluationResult::allowed())
            } else {
                Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()))
            }
        });
        policy
    }

    async fn build_state(cfg: Config, provider: Provider, policy_allow: bool) -> ServiceState {
        Arc::new(
            Service::new(
                ConfigManager::not_watched(cfg),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(mock_policy(policy_allow)),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        )
    }

    fn create_body(external_id: &str, user_id: &str) -> Body {
        let req = IdentityLinkCreateRequest {
            identity_link: IdentityLinkCreate {
                external_id: external_id.to_string(),
                user_id: user_id.to_string(),
            },
        };
        Body::from(serde_json::to_string(&req).unwrap())
    }

    async fn create_request(
        state: ServiceState,
        body: Body,
        authed: bool,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!("/{PLUGIN}/identity_links"))
            .header(header::CONTENT_TYPE, "application/json");
        if authed {
            builder = builder.extension(test_fixture_scoped());
        }
        openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap()
    }

    async fn delete_request(
        state: ServiceState,
        external_id: &str,
        authed: bool,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("DELETE")
            .uri(format!("/{PLUGIN}/identity_links/{external_id}"));
        if authed {
            builder = builder.extension(test_fixture_scoped());
        }
        openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// Happy path: a domain-admin links an existing, non-system user whose
    /// domain the plugin may provision into. 201 + echoed link.
    #[tokio::test]
    async fn test_create_link() {
        let mut identity = MockIdentityProvider::default();
        identity
            .expect_get_user()
            .returning(|_, _| Ok(Some(user_response(DOMAIN))));
        let mut assignment = MockAssignmentProvider::default();
        assignment
            .expect_list_role_assignments()
            .returning(|_, _| Ok(Vec::new()));
        let mut dpi = MockDynamicPluginIdentityProvider::default();
        dpi.expect_find().returning(|_, _, _| Ok(None));
        dpi.expect_create_or_resolve()
            .returning(|_, _, _, user_id| Ok(user_id.to_string()));

        let provider = Provider::mocked_builder()
            .mock_identity(identity)
            .mock_assignment(assignment)
            .mock_auth_plugin_identity(dpi)
            .build()
            .unwrap();
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::FullAuth, Some(DOMAIN)))),
            provider,
            true,
        )
        .await;

        let response = create_request(state, create_body("ext-1", "target-user"), true).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: IdentityLinkResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.identity_link.external_id, "ext-1");
        assert_eq!(res.identity_link.user_id, "target-user");
        assert_eq!(res.identity_link.plugin_name, PLUGIN);
    }

    /// Re-linking an `external_id` that already resolves is a 409, never a
    /// silent overwrite (ADR §4).
    #[tokio::test]
    async fn test_create_conflict_existing_link() {
        let mut identity = MockIdentityProvider::default();
        identity
            .expect_get_user()
            .returning(|_, _| Ok(Some(user_response(DOMAIN))));
        let mut assignment = MockAssignmentProvider::default();
        assignment
            .expect_list_role_assignments()
            .returning(|_, _| Ok(Vec::new()));
        let mut dpi = MockDynamicPluginIdentityProvider::default();
        dpi.expect_find()
            .returning(|_, _, _| Ok(Some("someone-else".to_string())));

        let provider = Provider::mocked_builder()
            .mock_identity(identity)
            .mock_assignment(assignment)
            .mock_auth_plugin_identity(dpi)
            .build()
            .unwrap();
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::FullAuth, Some(DOMAIN)))),
            provider,
            true,
        )
        .await;

        let response = create_request(state, create_body("ext-1", "target-user"), true).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    /// A policy denial (e.g. domain-admin linking a system principal) is a 403
    /// before any write.
    #[tokio::test]
    async fn test_create_policy_denied() {
        let mut identity = MockIdentityProvider::default();
        identity
            .expect_get_user()
            .returning(|_, _| Ok(Some(user_response(DOMAIN))));
        let mut assignment = MockAssignmentProvider::default();
        assignment
            .expect_list_role_assignments()
            .returning(|_, _| Ok(Vec::new()));

        let provider = Provider::mocked_builder()
            .mock_identity(identity)
            .mock_assignment(assignment)
            .build()
            .unwrap();
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::FullAuth, Some(DOMAIN)))),
            provider,
            false,
        )
        .await;

        let response = create_request(state, create_body("ext-1", "target-user"), true).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// No injected `ValidatedSecurityContext` -> the `Auth` extractor rejects
    /// with 401 before the handler runs.
    #[tokio::test]
    async fn test_create_unauthorized() {
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::FullAuth, Some(DOMAIN)))),
            Provider::mocked_builder().build().unwrap(),
            true,
        )
        .await;

        let response = create_request(state, create_body("ext-1", "target-user"), false).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A link can never place a user outside the plugin's configured
    /// provisioning domain (ADR §4) - rejected with 400 before policy.
    #[tokio::test]
    async fn test_create_domain_outside_plugin() {
        let mut identity = MockIdentityProvider::default();
        identity
            .expect_get_user()
            .returning(|_, _| Ok(Some(user_response(DOMAIN))));

        let provider = Provider::mocked_builder()
            .mock_identity(identity)
            .build()
            .unwrap();
        let state = build_state(
            config_with(Some(plugin_config(
                PluginMode::FullAuth,
                Some("other-domain"),
            ))),
            provider,
            true,
        )
        .await;

        let response = create_request(state, create_body("ext-1", "target-user"), true).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// A plugin name absent from config is a 404.
    #[tokio::test]
    async fn test_create_unknown_plugin() {
        let state = build_state(
            config_with(None),
            Provider::mocked_builder().build().unwrap(),
            true,
        )
        .await;

        let response = create_request(state, create_body("ext-1", "target-user"), true).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Linking a non-`full_auth` plugin is meaningless (only `full_auth`
    /// plugins call `find_user`) - rejected with 400.
    #[tokio::test]
    async fn test_create_non_full_auth_plugin() {
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::Mapping, None))),
            Provider::mocked_builder().build().unwrap(),
            true,
        )
        .await;

        let response = create_request(state, create_body("ext-1", "target-user"), true).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Linking a user that does not exist is a 404.
    #[tokio::test]
    async fn test_create_unknown_user() {
        let mut identity = MockIdentityProvider::default();
        identity.expect_get_user().returning(|_, _| Ok(None));

        let provider = Provider::mocked_builder()
            .mock_identity(identity)
            .build()
            .unwrap();
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::FullAuth, Some(DOMAIN)))),
            provider,
            true,
        )
        .await;

        let response = create_request(state, create_body("ext-1", "missing"), true).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Happy path: deleting a live link returns 204 and revokes the unlinked
    /// user's tokens (ADR §4). `create_revocation_event` asserted via
    /// `.times(1)`.
    #[tokio::test]
    async fn test_delete_link() {
        let mut dpi = MockDynamicPluginIdentityProvider::default();
        dpi.expect_find()
            .returning(|_, _, _| Ok(Some("target-user".to_string())));
        dpi.expect_purge().returning(|_, _, _| Ok(()));
        let mut identity = MockIdentityProvider::default();
        identity
            .expect_get_user()
            .returning(|_, _| Ok(Some(user_response(DOMAIN))));
        let mut assignment = MockAssignmentProvider::default();
        assignment
            .expect_list_role_assignments()
            .returning(|_, _| Ok(Vec::new()));
        let mut revoke = MockRevokeProvider::default();
        revoke
            .expect_create_revocation_event()
            .times(1)
            .returning(|_, _| Ok(RevocationEvent::default()));

        let provider = Provider::mocked_builder()
            .mock_identity(identity)
            .mock_assignment(assignment)
            .mock_auth_plugin_identity(dpi)
            .mock_revoke(revoke)
            .build()
            .unwrap();
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::FullAuth, Some(DOMAIN)))),
            provider,
            true,
        )
        .await;

        let response = delete_request(state, "ext-1", true).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    /// Deleting a link that does not exist is a 404.
    #[tokio::test]
    async fn test_delete_no_link() {
        let mut dpi = MockDynamicPluginIdentityProvider::default();
        dpi.expect_find().returning(|_, _, _| Ok(None));

        let provider = Provider::mocked_builder()
            .mock_auth_plugin_identity(dpi)
            .build()
            .unwrap();
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::FullAuth, Some(DOMAIN)))),
            provider,
            true,
        )
        .await;

        let response = delete_request(state, "ext-1", true).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// A policy denial on delete is a 403 and performs no purge/revocation.
    #[tokio::test]
    async fn test_delete_policy_denied() {
        let mut dpi = MockDynamicPluginIdentityProvider::default();
        dpi.expect_find()
            .returning(|_, _, _| Ok(Some("target-user".to_string())));
        dpi.expect_purge().times(0);
        let mut identity = MockIdentityProvider::default();
        identity
            .expect_get_user()
            .returning(|_, _| Ok(Some(user_response(DOMAIN))));
        let mut assignment = MockAssignmentProvider::default();
        assignment
            .expect_list_role_assignments()
            .returning(|_, _| Ok(Vec::new()));
        let mut revoke = MockRevokeProvider::default();
        revoke.expect_create_revocation_event().times(0);

        let provider = Provider::mocked_builder()
            .mock_identity(identity)
            .mock_assignment(assignment)
            .mock_auth_plugin_identity(dpi)
            .mock_revoke(revoke)
            .build()
            .unwrap();
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::FullAuth, Some(DOMAIN)))),
            provider,
            false,
        )
        .await;

        let response = delete_request(state, "ext-1", true).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // --- revoke_all -------------------------------------------------------
    //
    // These exercise the sibling `revoke_all` handler through the same
    // `openapi_router()` (which now wires it) and reuse the helpers above
    // rather than re-declaring the 20-field `plugin_config`. The system-admin
    // rego gating is exercised at the real-server layer; here the enforcer is
    // mocked exactly as the identity-link tests do.

    async fn revoke_all_request(state: ServiceState, authed: bool) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!("/{PLUGIN}/revoke_all"));
        if authed {
            builder = builder.extension(test_fixture_scoped());
        }
        openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// Happy path: two links to two distinct users. Each user is disabled and
    /// its tokens revoked once; every link is deleted. 200 + counts.
    #[tokio::test]
    async fn test_revoke_all_disables_and_revokes() {
        let mut dpi = MockDynamicPluginIdentityProvider::default();
        dpi.expect_list_by_plugin().returning(|_, _| {
            Ok(vec![
                ("ext-1".to_string(), "u1".to_string()),
                ("ext-2".to_string(), "u2".to_string()),
            ])
        });
        dpi.expect_purge().times(2).returning(|_, _, _| Ok(()));
        let mut identity = MockIdentityProvider::default();
        identity
            .expect_get_user()
            .returning(|_, _| Ok(Some(user_response(DOMAIN))));
        identity
            .expect_update_user()
            .times(2)
            .returning(|_, _, _| Ok(user_response(DOMAIN)));
        let mut revoke = MockRevokeProvider::default();
        revoke
            .expect_create_revocation_event()
            .times(2)
            .returning(|_, _| Ok(RevocationEvent::default()));

        let provider = Provider::mocked_builder()
            .mock_identity(identity)
            .mock_auth_plugin_identity(dpi)
            .mock_revoke(revoke)
            .build()
            .unwrap();
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::FullAuth, Some(DOMAIN)))),
            provider,
            true,
        )
        .await;

        let response = revoke_all_request(state, true).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RevokeAllResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.revoke_all.users_disabled, 2);
        assert_eq!(res.revoke_all.links_deleted, 2);
    }

    /// Two links pointing at the same user: the user is disabled/revoked once
    /// (de-duped), but both link entries are still deleted.
    #[tokio::test]
    async fn test_revoke_all_dedupes_users() {
        let mut dpi = MockDynamicPluginIdentityProvider::default();
        dpi.expect_list_by_plugin().returning(|_, _| {
            Ok(vec![
                ("ext-1".to_string(), "u1".to_string()),
                ("ext-2".to_string(), "u1".to_string()),
            ])
        });
        dpi.expect_purge().times(2).returning(|_, _, _| Ok(()));
        let mut identity = MockIdentityProvider::default();
        identity
            .expect_get_user()
            .times(1)
            .returning(|_, _| Ok(Some(user_response(DOMAIN))));
        identity
            .expect_update_user()
            .times(1)
            .returning(|_, _, _| Ok(user_response(DOMAIN)));
        let mut revoke = MockRevokeProvider::default();
        revoke
            .expect_create_revocation_event()
            .times(1)
            .returning(|_, _| Ok(RevocationEvent::default()));

        let provider = Provider::mocked_builder()
            .mock_identity(identity)
            .mock_auth_plugin_identity(dpi)
            .mock_revoke(revoke)
            .build()
            .unwrap();
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::FullAuth, Some(DOMAIN)))),
            provider,
            true,
        )
        .await;

        let response = revoke_all_request(state, true).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RevokeAllResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.revoke_all.users_disabled, 1);
        assert_eq!(res.revoke_all.links_deleted, 2);
    }

    /// A plugin with no remaining state is a 200 no-op with all-zero counts
    /// (idempotent; safe to re-run in a runbook, ADR §4).
    #[tokio::test]
    async fn test_revoke_all_empty_is_noop() {
        let mut dpi = MockDynamicPluginIdentityProvider::default();
        dpi.expect_list_by_plugin().returning(|_, _| Ok(Vec::new()));
        dpi.expect_purge().times(0);
        let mut identity = MockIdentityProvider::default();
        identity.expect_update_user().times(0);
        let mut revoke = MockRevokeProvider::default();
        revoke.expect_create_revocation_event().times(0);

        let provider = Provider::mocked_builder()
            .mock_identity(identity)
            .mock_auth_plugin_identity(dpi)
            .mock_revoke(revoke)
            .build()
            .unwrap();
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::FullAuth, Some(DOMAIN)))),
            provider,
            true,
        )
        .await;

        let response = revoke_all_request(state, true).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RevokeAllResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.revoke_all.users_disabled, 0);
        assert_eq!(res.revoke_all.links_deleted, 0);
    }

    /// A policy denial is a 403 and touches no state: no enumeration, disable,
    /// revocation, or purge.
    #[tokio::test]
    async fn test_revoke_all_policy_denied() {
        let mut dpi = MockDynamicPluginIdentityProvider::default();
        dpi.expect_list_by_plugin().times(0);
        dpi.expect_purge().times(0);
        let mut identity = MockIdentityProvider::default();
        identity.expect_update_user().times(0);
        let mut revoke = MockRevokeProvider::default();
        revoke.expect_create_revocation_event().times(0);

        let provider = Provider::mocked_builder()
            .mock_identity(identity)
            .mock_auth_plugin_identity(dpi)
            .mock_revoke(revoke)
            .build()
            .unwrap();
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::FullAuth, Some(DOMAIN)))),
            provider,
            false,
        )
        .await;

        let response = revoke_all_request(state, true).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// No security context -> 401 before any handler logic runs.
    #[tokio::test]
    async fn test_revoke_all_unauthorized() {
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::FullAuth, Some(DOMAIN)))),
            Provider::mocked_builder().build().unwrap(),
            true,
        )
        .await;

        let response = revoke_all_request(state, false).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// An unconfigured plugin name is a 404.
    #[tokio::test]
    async fn test_revoke_all_unknown_plugin() {
        let state = build_state(
            config_with(None),
            Provider::mocked_builder().build().unwrap(),
            true,
        )
        .await;

        let response = revoke_all_request(state, true).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// revoke_all is meaningless for a non-full_auth plugin (it never
    /// provisions or links) -> 400.
    #[tokio::test]
    async fn test_revoke_all_non_full_auth() {
        let state = build_state(
            config_with(Some(plugin_config(PluginMode::Mapping, None))),
            Provider::mocked_builder().build().unwrap(),
            true,
        )
        .await;

        let response = revoke_all_request(state, true).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
