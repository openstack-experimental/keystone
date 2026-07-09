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

use std::collections::HashMap;
use std::net::IpAddr;

use openstack_keystone_config::PluginMode;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::dynamic_plugin_auth::{
    WasmPluginAuthError, WasmPluginAuthRequest, authenticate_via_wasm_mapping_plugin,
    authenticate_via_wasm_plugin, route_via_wasm_plugin,
};

use crate::api::error::KeystoneApiError;
use crate::api::v3::auth::token::types::AuthRequest;
use crate::auth::*;
use crate::keystone::ServiceState;

/// Authenticate the user ignoring any scope information. It is important not to
/// expose any hints that user, project, domain, etc might exist before we have
/// authenticated them by taking different amount of time in case of certain
/// validations.
#[tracing::instrument(skip(state, headers), err)]
pub(super) async fn authenticate_request(
    state: &ServiceState,
    req: &AuthRequest,
    headers: &axum::http::HeaderMap,
    peer_ip: Option<IpAddr>,
) -> Result<Vec<AuthenticationResult>, KeystoneApiError> {
    let raw_headers: HashMap<String, String> = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect();
    let xff_header = headers
        .get(axum::http::header::HeaderName::from_static(
            "x-forwarded-for",
        ))
        .and_then(|h| h.to_str().ok())
        .map(str::to_string);

    // Pre-dispatch `route` mode (ADR 0025 §4 "Guest Contract - `route`
    // Mode"): runs once, before any builtin/plugin method dispatch, and may
    // relabel which already-registered method actually handles the request
    // (the Terraform `application_credential`-shaped-auth case, where the
    // client can't be made to name a custom method itself). Only the first
    // configured `mode = route` plugin whose `inspect_methods` intersects
    // the client's `identity.methods` runs - single-shot falls out of this
    // being a single pre-pass with no recursion, not an explicit flag.
    let mut effective_methods = req.auth.identity.methods.clone();
    let mut effective_extra = req.auth.identity.extra.clone();
    {
        let router = {
            let cfg = state.config_manager.config.read().await;
            cfg.dynamic_plugin
                .iter()
                .filter(|(_, p)| p.mode == PluginMode::Route)
                .find(|(_, p)| {
                    p.inspect_methods
                        .iter()
                        .any(|m| effective_methods.contains(m))
                })
                .map(|(name, p)| (name.clone(), p.inspect_methods.clone()))
        };
        if let Some((router_name, inspect_methods)) = router {
            let inspected: Vec<String> = inspect_methods
                .into_iter()
                .filter(|m| effective_methods.contains(m))
                .collect();
            let payloads: HashMap<String, serde_json::Value> = inspected
                .iter()
                .filter_map(|m| effective_extra.get(m).map(|v| (m.clone(), v.clone())))
                .collect();
            match route_via_wasm_plugin(
                state,
                &router_name,
                &effective_methods,
                payloads,
                raw_headers.clone(),
                xff_header.clone(),
                peer_ip,
            )
            .await
            {
                Ok(decision) => {
                    if let (Some(target), Some(payload)) =
                        (decision.target_method, decision.payload)
                    {
                        effective_methods.retain(|m| !inspected.contains(m));
                        for m in &inspected {
                            effective_extra.remove(m);
                        }
                        if !effective_methods.contains(&target) {
                            effective_methods.push(target.clone());
                        }
                        effective_extra.insert(target, payload);
                    }
                    // `Passthrough` (both `None`) leaves `effective_methods`/
                    // `effective_extra` untouched.
                }
                Err(WasmPluginAuthError::RateLimited(_)) => {
                    return Err(KeystoneApiError::TooManyRequests);
                }
                // Denied/malformed/etc fail the whole request closed - never
                // fall through to dispatching the original, un-routed
                // request (ADR §4 constraint 6 "Fail-closed").
                Err(_) => return Err(KeystoneApiError::UnauthorizedNoContext),
            }
        }
    }

    let mut res = Vec::new();
    for method in effective_methods.iter() {
        if method == "password" {
            if let Some(password_auth) = &req.auth.identity.password {
                let req = password_auth.user.clone().try_into()?;
                res.push(
                    state
                        .provider
                        .get_identity_provider()
                        .authenticate_by_password(&ExecutionContext::internal(state), &req)
                        .await?,
                );
            }
        } else if method == "totp" {
            if let Some(totp_auth) = &req.auth.identity.totp {
                let req = totp_auth.user.clone().try_into()?;
                res.push(
                    state
                        .provider
                        .get_identity_provider()
                        .authenticate_by_totp(&ExecutionContext::internal(state), &req)
                        .await?,
                );
            }
        } else if method == "token"
            && let Some(token) = &req.auth.identity.token
        {
            let vsc = state
                .provider
                .get_token_provider()
                .authorize_by_token(
                    &ExecutionContext::internal(state),
                    &token.id,
                    Some(false),
                    None,
                )
                .await?;
            let auth_res = AuthenticationResult {
                audit_id: vsc.inner().audit_ids().first().cloned().unwrap_or_default(),
                context: vsc.inner().authentication_context().clone(),
                expires_at: vsc.inner().expires_at(),
                principal: vsc.inner().principal().clone(),
                authorization: vsc.inner().authorization().cloned(),
                token_restriction: vsc.inner().token_restriction().cloned(),
            };
            res.push(auth_res);
        } else if let Some(payload) = effective_extra.get(method) {
            // Unrecognized method name with a matching request body block -
            // dispatch to a loaded `mode = full_auth` dynamic auth plugin
            // (ADR 0025 §4). `NotFound`/`WrongMode` degrade to the same
            // silent skip an unmatched builtin method already gets;
            // anything else fails the whole request closed (ADR §7) - a
            // plugin's internal denial reason is never surfaced here, only
            // audited.
            let plugin_mode = state
                .config_manager
                .config
                .read()
                .await
                .dynamic_plugin
                .get(method)
                .map(|p| p.mode);
            let wasm_request = WasmPluginAuthRequest {
                payload: payload.clone(),
                raw_headers: raw_headers.clone(),
                xff_header: xff_header.clone(),
                peer_ip,
            };
            let dispatch_result = match plugin_mode {
                Some(PluginMode::Mapping) => {
                    authenticate_via_wasm_mapping_plugin(state, method, wasm_request).await
                }
                // `None` (plugin not configured at all) still goes through
                // `authenticate_via_wasm_plugin` so its own `NotFound` path
                // is the single source of truth for "no such plugin" - not
                // duplicated here.
                _ => authenticate_via_wasm_plugin(state, method, wasm_request).await,
            };
            match dispatch_result {
                Ok(auth_res) => res.push(auth_res),
                Err(WasmPluginAuthError::NotFound | WasmPluginAuthError::WrongMode) => {}
                Err(WasmPluginAuthError::RateLimited(_)) => {
                    return Err(KeystoneApiError::TooManyRequests);
                }
                Err(_) => return Err(KeystoneApiError::UnauthorizedNoContext),
            }
        }
    }
    if res.is_empty() {
        return Err(KeystoneApiError::UnauthorizedNoContext);
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::auth::*;
    use openstack_keystone_core_types::identity::{UserPasswordAuthRequest, UserResponseBuilder};
    use openstack_keystone_core_types::resource::Domain;
    use secrecy::ExposeSecret;

    use super::super::types::*;
    use super::*;
    use crate::api::KeystoneApiError;
    use crate::api::tests::get_mocked_state;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::token::MockTokenProvider;

    #[tokio::test]
    async fn test_authenticate_request_password() {
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap();
        let auth_clone = auth.clone();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .withf(|_, req: &UserPasswordAuthRequest| {
                req.id == Some("uid".to_string())
                    && req.password.expose_secret() == "pwd"
                    && req.name == Some("uname".to_string())
            })
            .returning(move |_, _| Ok(auth_clone.clone()));

        let provider = Provider::mocked_builder().mock_identity(identity_mock);

        let state = get_mocked_state(provider, true, None).await;

        assert_eq!(
            vec![auth],
            authenticate_request(
                &state,
                &AuthRequest {
                    auth: AuthRequestInner {
                        identity: Identity {
                            methods: vec!["password".to_string()],
                            password: Some(PasswordAuth {
                                user: UserPasswordBuilder::default()
                                    .id("uid")
                                    .password("pwd")
                                    .name("uname")
                                    .build()
                                    .unwrap(),
                            }),
                            token: None,
                            totp: None,
                            extra: Default::default(),
                        },
                        scope: None,
                    },
                },
                &axum::http::HeaderMap::new(),
                None,
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_authenticate_request_totp() {
        use openstack_keystone_core_types::identity::UserTotpAuthRequest;

        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Totp)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap();
        let auth_clone = auth.clone();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_totp()
            .withf(|_, req: &UserTotpAuthRequest| {
                req.id == Some("uid".to_string()) && req.passcode.expose_secret() == "123456"
            })
            .returning(move |_, _| Ok(auth_clone.clone()));

        let provider = Provider::mocked_builder().mock_identity(identity_mock);

        let state = get_mocked_state(provider, true, None).await;

        assert_eq!(
            vec![auth],
            authenticate_request(
                &state,
                &AuthRequest {
                    auth: AuthRequestInner {
                        identity: Identity {
                            methods: vec!["totp".to_string()],
                            password: None,
                            token: None,
                            totp: Some(TotpAuth {
                                user: TotpUserBuilder::default()
                                    .id("uid")
                                    .passcode("123456")
                                    .build()
                                    .unwrap(),
                            }),
                            extra: Default::default(),
                        },
                        scope: None,
                    },
                },
                &axum::http::HeaderMap::new(),
                None,
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_authenticate_request_token() {
        let user = UserResponseBuilder::default()
            .id("uid")
            .domain_id("user_domain_id")
            .enabled(true)
            .name("name")
            .build()
            .unwrap();
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Token(
                openstack_keystone_core_types::token::FernetToken::Unscoped(
                    openstack_keystone_core_types::token::UnscopedPayload::default(),
                ),
            ))
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .user(user.clone())
                        .user_domain(Domain {
                            id: "user_domain_id".into(),
                            enabled: true,
                            ..Default::default()
                        })
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap();
        let vsc_for_mock = {
            let sc = SecurityContext::try_from(auth.clone()).unwrap();
            openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
        };
        let vsc_clone = vsc_for_mock.clone();
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_authorize_by_token()
            .withf(
                |_,
                 _id: &secrecy::SecretString,
                 allow_expired: &Option<bool>,
                 window: &Option<i64>| {
                    *allow_expired == Some(false) && window.is_none()
                },
            )
            .returning(move |_state, _, _, _| Ok(vsc_clone.clone()));
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_exec, id: &'_ str| id == "uid")
            .returning(move |_exec, _| Ok(Some(user.clone())));

        let provider = Provider::mocked_builder()
            .mock_identity(identity_mock)
            .mock_token(token_mock);

        let state = get_mocked_state(provider, true, None).await;

        assert_eq!(
            vec![auth],
            authenticate_request(
                &state,
                &AuthRequest {
                    auth: AuthRequestInner {
                        identity: Identity {
                            methods: vec!["token".to_string()],
                            password: None,
                            token: Some(TokenAuth {
                                id: "fake_token".into()
                            }),
                            totp: None,
                            extra: Default::default(),
                        },
                        scope: None,
                    },
                },
                &axum::http::HeaderMap::new(),
                None,
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_authenticate_request_unsupported() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let rsp = authenticate_request(
            &state,
            &AuthRequest {
                auth: AuthRequestInner {
                    identity: Identity {
                        methods: vec!["fake".to_string()],
                        password: None,
                        token: None,
                        totp: None,
                        extra: Default::default(),
                    },
                    scope: None,
                },
            },
            &axum::http::HeaderMap::new(),
            None,
        )
        .await;
        if let KeystoneApiError::UnauthorizedNoContext = rsp.unwrap_err() {
        } else {
            panic!("Should receive Unauthorized");
        }
    }
}

/// End-to-end acceptance tests for the pre-dispatch `route` mode pass
/// (ADR 0025 §4 "Guest Contract - `route` Mode") against the real, compiled
/// reference plugin - mirrors Phase 3's exit criteria (a)-(e) verbatim.
/// Builds `ServiceState` directly (not `get_mocked_state`, which uses
/// `Config::default()` and can't carry a `[dynamic_plugin.*]` section) with
/// two loaded reference-plugin instances: `router` (`mode = route`,
/// `inspect_methods = application_credential`, `route_targets =
/// tf_appcred_handler`) and `tf_appcred_handler` (`mode = full_auth`) - the
/// allowlisted target the router may redirect to.
#[cfg(test)]
mod route_dispatch_tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;

    use openstack_keystone_config::{Config, ConfigManager, DynamicPluginsSection};
    use openstack_keystone_core::dynamic_plugin_http::DynamicPluginHttpFetcher;
    use openstack_keystone_core::dynamic_plugin_startup::load_dynamic_plugins;
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use sha2::{Digest, Sha256};

    use super::super::types::*;
    use super::*;
    use crate::dynamic_plugin_identity::MockDynamicPluginIdentityProvider;
    use crate::identity::MockIdentityProvider;
    use crate::keystone::{AuditDispatcher, Service};
    use crate::policy::MockPolicy;
    use crate::provider::Provider;

    struct UnreachableHttpFetcher;

    #[async_trait::async_trait]
    impl DynamicPluginHttpFetcher for UnreachableHttpFetcher {
        async fn fetch(
            &self,
            _method: &str,
            _url: &str,
            _resolved_addr: std::net::SocketAddr,
            _headers: &HashMap<String, String>,
            _body: Option<&str>,
            _timeout_ms: u64,
            _auth_header: Option<(&str, &str)>,
            _max_body_bytes: usize,
        ) -> Result<openstack_keystone_core::dynamic_plugin_http::FetchResponse, String> {
            panic!("this test's plugins don't grant http_fetch")
        }
    }

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../dynamic-plugin-runtime/tests/fixtures/reference-plugin")
    }

    fn build_reference_plugin() -> (PathBuf, String) {
        let dir = fixture_dir();
        let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()))
            .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
            .current_dir(&dir)
            .status()
            .expect("failed to spawn cargo to build the reference plugin fixture");
        assert!(
            status.success(),
            "building the reference plugin fixture failed"
        );

        let wasm_path = dir.join("target/wasm32-unknown-unknown/release/reference_plugin.wasm");
        assert!(
            wasm_path.is_file(),
            "expected build artifact at {}",
            wasm_path.display()
        );
        let bytes = std::fs::read(&wasm_path).unwrap();
        let sha256 = {
            use std::fmt::Write;
            Sha256::digest(&bytes)
                .iter()
                .fold(String::new(), |mut acc, b| {
                    let _ = write!(acc, "{b:02x}");
                    acc
                })
        };
        (wasm_path, sha256)
    }

    fn user_response(
        id: &str,
        domain_id: &str,
    ) -> openstack_keystone_core_types::identity::UserResponse {
        UserResponseBuilder::default()
            .id(id.to_string())
            .domain_id(domain_id.to_string())
            .name("dave".to_string())
            .enabled(true)
            .build()
            .unwrap()
    }

    /// Base `DynamicPluginConfig` with every non-essential field at its
    /// documented default (`crates/config/src/dynamic_plugins.rs`) - no
    /// `Default` impl exists on the struct itself, so tests fill it in
    /// directly rather than round-tripping through the `config` crate's INI
    /// parser (an actual dependency of `openstack-keystone-config`, not of
    /// this crate).
    fn base_plugin_config(
        path: PathBuf,
        sha256: String,
        mode: openstack_keystone_config::PluginMode,
    ) -> openstack_keystone_config::DynamicPluginConfig {
        openstack_keystone_config::DynamicPluginConfig {
            path,
            sha256,
            mode,
            capabilities: Vec::new(),
            exposed_headers: Vec::new(),
            allowed_hosts: Vec::new(),
            http_fetch_follow_redirects: false,
            http_fetch_auth_header: None,
            http_fetch_auth_secret_env: None,
            provision_domain_id: None,
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

    /// Loads the reference plugin twice under one `ServiceState`: as
    /// `router` (`mode = route`) and as `tf_appcred_handler`
    /// (`mode = full_auth`, the router's sole `route_targets` entry).
    async fn build_route_state(
        identity_mock: MockIdentityProvider,
        dpi_mock: MockDynamicPluginIdentityProvider,
    ) -> ServiceState {
        let (path, sha256) = build_reference_plugin();

        let mut router_config = base_plugin_config(
            path.clone(),
            sha256.clone(),
            openstack_keystone_config::PluginMode::Route,
        );
        router_config.inspect_methods = vec!["application_credential".to_string()];
        router_config.route_targets = vec!["tf_appcred_handler".to_string()];

        let mut target_config = base_plugin_config(
            path,
            sha256,
            openstack_keystone_config::PluginMode::FullAuth,
        );
        target_config.capabilities = vec!["provision_user".to_string()];
        target_config.provision_domain_id = Some("d".to_string());

        let cfg = Config {
            dynamic_plugins: DynamicPluginsSection {
                plugins: vec!["router".to_string(), "tf_appcred_handler".to_string()],
                ..Default::default()
            },
            dynamic_plugin: [
                ("router".to_string(), router_config),
                ("tf_appcred_handler".to_string(), target_config),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };

        let (audit_dispatcher, receivers) = AuditDispatcher::new(
            "test-node",
            uuid::Uuid::new_v4().to_string(),
            Arc::from(b"test-hmac-key-32-bytes-long!!!!".as_slice()),
            0,
        );
        std::mem::forget(receivers);

        let provider = Provider::mocked_builder()
            .mock_identity(identity_mock)
            .mock_dynamic_plugin_identity(dpi_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(cfg),
                sea_orm::DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                audit_dispatcher,
                None,
            )
            .await
            .unwrap(),
        );

        load_dynamic_plugins(&state, Arc::new(UnreachableHttpFetcher)).await;
        for name in ["router", "tf_appcred_handler"] {
            assert!(
                state.dynamic_plugin_registry.read().await.contains(name),
                "reference plugin {name} should have loaded"
            );
        }
        state
    }

    fn appcred_request(cred_id: &str) -> AuthRequest {
        let mut extra = std::collections::HashMap::new();
        extra.insert(
            "application_credential".to_string(),
            serde_json::json!({"application_credential_id": cred_id}),
        );
        AuthRequest {
            auth: AuthRequestInner {
                identity: Identity {
                    methods: vec!["application_credential".to_string()],
                    password: None,
                    token: None,
                    totp: None,
                    extra,
                },
                scope: None,
            },
        }
    }

    fn permissive_mocks() -> (MockIdentityProvider, MockDynamicPluginIdentityProvider) {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_create_user()
            .returning(|_, _| Ok(user_response("u1", "d")));
        identity_mock
            .expect_get_user()
            .returning(|_, _| Ok(Some(user_response("u1", "d"))));
        identity_mock
            .expect_get_user_domain_id()
            .returning(|_, _| Ok("d".to_string()));

        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock.expect_find().returning(|_, _, _| Ok(None));
        dpi_mock
            .expect_create_or_resolve()
            .returning(|_, _, _, user_id| Ok(user_id.to_string()));

        (identity_mock, dpi_mock)
    }

    /// (a) A `password`-only request never invokes the router, even though
    /// the router is loaded and configured - it's simply never triggered
    /// (`inspect_methods` doesn't intersect `identity.methods`), so this
    /// falls through to the same "unsupported method" outcome any
    /// unconfigured `password` attempt with no `password` block gets.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_password_only_request_never_triggers_router() {
        let (identity_mock, dpi_mock) = permissive_mocks();
        let state = build_route_state(identity_mock, dpi_mock).await;

        let rsp = authenticate_request(
            &state,
            &AuthRequest {
                auth: AuthRequestInner {
                    identity: Identity {
                        methods: vec!["password".to_string()],
                        password: None,
                        token: None,
                        totp: None,
                        extra: Default::default(),
                    },
                    scope: None,
                },
            },
            &axum::http::HeaderMap::new(),
            None,
        )
        .await;
        assert!(matches!(
            rsp.unwrap_err(),
            KeystoneApiError::UnauthorizedNoContext
        ));
    }

    /// (b) A `Route` response to an allowlisted target correctly redispatches
    /// and the target still independently processes the (relabeled) payload
    /// - proven by the resulting `AuthenticationContext::WasmPlugin` naming
    /// `tf_appcred_handler`, not `router`.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_route_to_allowlisted_target_redispatches() {
        let (identity_mock, dpi_mock) = permissive_mocks();
        let state = build_route_state(identity_mock, dpi_mock).await;

        let res = authenticate_request(
            &state,
            &appcred_request("tf-alice"),
            &axum::http::HeaderMap::new(),
            None,
        )
        .await
        .expect("routed request should dispatch to the allowlisted target and succeed");
        assert_eq!(res.len(), 1);
        let AuthenticationContext::WasmPlugin { plugin_name, .. } = &res[0].context else {
            panic!("expected WasmPlugin context");
        };
        assert_eq!(plugin_name, "tf_appcred_handler");
    }

    /// (c) A `Route` naming a target outside `route_targets` is rejected,
    /// not redirected - the request never reaches any dispatch that could
    /// provision a user.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_off_allowlist_target_is_rejected() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_create_user().times(0);
        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock.expect_create_or_resolve().times(0);
        let state = build_route_state(identity_mock, dpi_mock).await;

        // Reconfigure the router's `route_targets` to no longer include
        // `tf_appcred_handler` - simplest way to force an off-allowlist
        // response from the same fixture without a second wasm binary.
        {
            let mut cfg = state.config_manager.config.write().await;
            if let Some(router_cfg) = cfg.dynamic_plugin.get_mut("router") {
                router_cfg.route_targets = vec!["some_other_target".to_string()];
            }
        }

        let rsp = authenticate_request(
            &state,
            &appcred_request("tf-alice"),
            &axum::http::HeaderMap::new(),
            None,
        )
        .await;
        assert!(matches!(
            rsp.unwrap_err(),
            KeystoneApiError::UnauthorizedNoContext
        ));
    }

    /// (e) A router `Deny` fails the whole request closed without falling
    /// through to dispatching the original, un-routed `application_credential`
    /// request.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_router_deny_fails_closed() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_create_user().times(0);
        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock.expect_create_or_resolve().times(0);
        let state = build_route_state(identity_mock, dpi_mock).await;

        let rsp = authenticate_request(
            &state,
            &appcred_request("deny-me"),
            &axum::http::HeaderMap::new(),
            None,
        )
        .await;
        assert!(matches!(
            rsp.unwrap_err(),
            KeystoneApiError::UnauthorizedNoContext
        ));
    }

    /// (d) Single-shot: the routed request's `effective_methods` going into
    /// the per-method loop no longer contains the original triggering
    /// method (`application_credential`) - only the target
    /// (`tf_appcred_handler`) - proven indirectly by the resulting
    /// `AuthenticationContext` naming only the target plugin, with exactly
    /// one result pushed (no second, redundant dispatch of the original
    /// method).
    #[tokio::test(flavor = "multi_thread")]
    async fn test_routed_request_is_single_shot() {
        let (identity_mock, dpi_mock) = permissive_mocks();
        let state = build_route_state(identity_mock, dpi_mock).await;

        let res = authenticate_request(
            &state,
            &appcred_request("tf-bob"),
            &axum::http::HeaderMap::new(),
            None,
        )
        .await
        .expect("routed request should succeed exactly once");
        assert_eq!(
            res.len(),
            1,
            "the original application_credential method must not also be dispatched"
        );
    }
}
