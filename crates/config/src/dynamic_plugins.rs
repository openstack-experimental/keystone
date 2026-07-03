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
//! # Keystone configuration
//!
//! Parsing and validation of the `[dynamic_plugins]` / `[dynamic_plugin.*]`
//! configuration sections introduced by ADR 0025 ("Dynamic Auth Plugins via
//! WebAssembly"). This module only covers config *shape* and the
//! config-load-time invariants the ADR calls out as fail-loud (§4, §5) - it
//! does not load or execute any plugin bytecode.
use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;
use thiserror::Error;

use crate::common::csv;

/// Auth method names that are compiled into `keystone-rs` and can therefore
/// never be shadowed by a dynamic plugin name, per ADR 0025 §4 "Reserved
/// Auth-Method Names".
pub const RESERVED_AUTH_METHOD_NAMES: &[&str] = &[
    "password",
    "token",
    "openid",
    "application_credential",
    "trust",
    "webauthn",
    "mapped",
    "k8s",
    "admin",
];

/// Auth methods a `route`-mode plugin's `route_targets` may never name,
/// regardless of what the plugin's own config otherwise allows - ADR 0025
/// §4 "Reserved Auth-Method Names": neither is a method a router's blast
/// radius should ever be able to reach.
pub const ROUTE_TARGET_FORBIDDEN_NAMES: &[&str] = &["admin", "trust"];

/// HTTP headers that can never appear in a plugin's `exposed_headers` list,
/// regardless of operator configuration - ADR 0025 §4 "Guest Contract -
/// `full_auth` Mode".
pub const HARD_DENYLISTED_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "x-auth-token",
    "x-service-token",
    "x-subject-token",
    "proxy-authorization",
];

/// The three host-function capabilities a plugin can be granted, per ADR
/// 0025 §6 (A-D; §6.E auditing is mandatory infrastructure, not a granted
/// capability, and therefore has no entry here).
pub const KNOWN_CAPABILITIES: &[&str] =
    &["http_fetch", "provision_user", "find_user", "assign_role"];

/// A dynamic auth plugin's operating mode - ADR 0025 §4 "Three Operating
/// Modes".
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginMode {
    /// The plugin is the terminal identity authority for its method name.
    #[default]
    FullAuth,
    /// The plugin only produces claims for the Unified Mapping Engine
    /// (ADR 0020) to evaluate.
    Mapping,
    /// The plugin runs pre-dispatch and may only relabel `identity.methods`
    /// and hand a payload to one allowlisted target method.
    Route,
}

/// `[dynamic_plugins]` section: the list of configured plugin names, each of
/// which must have a corresponding `[dynamic_plugin.<name>]` section.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct DynamicPluginsSection {
    /// Names of the dynamic plugins to load at startup. Each entry must
    /// have a matching `[dynamic_plugin.<name>]` section.
    #[serde(default, deserialize_with = "csv")]
    pub plugins: Vec<String>,
}

/// A single `[dynamic_plugin.<name>]` section - ADR 0025 §5.
#[derive(Debug, Deserialize, Clone)]
pub struct DynamicPluginConfig {
    /// Local filesystem path to the compiled `.wasm` module.
    pub path: PathBuf,

    /// Lowercase hex-encoded SHA-256 of the file at `path`, pinned at
    /// config time. A mismatch at load time disables only this plugin
    /// (ADR 0025 §5) - it is not validated against the filesystem here,
    /// only checked for well-formedness.
    pub sha256: String,

    /// Operating mode - defaults to `full_auth` (ADR 0025 §4).
    #[serde(default)]
    pub mode: PluginMode,

    /// Host functions (ADR 0025 §6 A-D) this plugin may call. An unlisted
    /// function is not registered into the plugin's `extism::Plugin`
    /// instance at all.
    #[serde(default, deserialize_with = "csv")]
    pub capabilities: Vec<String>,

    /// Allowlisted subset of inbound HTTP headers forwarded to the guest.
    /// Never allowed to contain a `HARD_DENYLISTED_HEADERS` entry.
    #[serde(default, deserialize_with = "csv")]
    pub exposed_headers: Vec<String>,

    /// Hostnames the `http_fetch` capability may connect to.
    #[serde(default, deserialize_with = "csv")]
    pub allowed_hosts: Vec<String>,

    /// Whether `http_fetch` follows redirects (each hop re-validated
    /// against `allowed_hosts` and the SSRF IP-range check). Defaults to
    /// `false` - ADR 0025 §6.A.
    #[serde(default)]
    pub http_fetch_follow_redirects: bool,

    /// Header name the host attaches to every outbound `http_fetch`
    /// request, if set.
    #[serde(default)]
    pub http_fetch_auth_header: Option<String>,

    /// Host-side environment variable the outbound secret value is read
    /// from. Never placed in guest memory (ADR 0025 §6.A).
    #[serde(default)]
    pub http_fetch_auth_secret_env: Option<String>,

    /// Domain `provision_user` may create users in. Mutually additive with
    /// `allowed_provision_domains` (ADR 0025 §6.B) - at least one of the two
    /// must be set for a plugin holding `provision_user`/`find_user`.
    #[serde(default)]
    pub provision_domain_id: Option<String>,

    /// Small explicit list of domains `provision_user` may create users in,
    /// for plugins that genuinely need more than one (ADR 0025 §6.B).
    #[serde(default, deserialize_with = "csv")]
    pub allowed_provision_domains: Vec<String>,

    /// Role names `assign_role` may grant (ADR 0025 §6.D).
    #[serde(default, deserialize_with = "csv")]
    pub assign_role_allowed: Vec<String>,

    /// `route` mode only: `identity.methods` entries that trigger this
    /// plugin's invocation (ADR 0025 §4 "Guest Contract - `route` Mode").
    #[serde(default, deserialize_with = "csv")]
    pub inspect_methods: Vec<String>,

    /// `route` mode only: auth methods this plugin is permitted to reroute
    /// a request to.
    #[serde(default, deserialize_with = "csv")]
    pub route_targets: Vec<String>,

    /// Wall-clock deadline for a single invocation, including any
    /// `http_fetch` calls (ADR 0025 §7).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Fuel (instruction count) limit for a single invocation.
    #[serde(default = "default_fuel_limit")]
    pub fuel_limit: u64,

    /// Linear memory cap, in MiB, for a single invocation.
    #[serde(default = "default_memory_limit_mb")]
    pub memory_limit_mb: u32,

    /// Per-`(plugin_name, remote_addr)` token bucket, checked before the
    /// plugin-wide bucket (ADR 0025 §7).
    #[serde(default = "default_rate_limit_per_source_per_minute")]
    pub invocation_rate_limit_per_source_per_minute: u32,

    /// Per-plugin token bucket, shared across all sources.
    #[serde(default = "default_rate_limit_per_minute")]
    pub invocation_rate_limit_per_minute: u32,

    /// Concurrency cap on in-flight invocations for this plugin.
    #[serde(default = "default_max_concurrent_invocations")]
    pub max_concurrent_invocations: u32,
}

fn default_timeout_ms() -> u64 {
    1_000
}

fn default_fuel_limit() -> u64 {
    10_000_000
}

fn default_memory_limit_mb() -> u32 {
    16
}

fn default_rate_limit_per_source_per_minute() -> u32 {
    20
}

fn default_rate_limit_per_minute() -> u32 {
    300
}

fn default_max_concurrent_invocations() -> u32 {
    16
}

/// A `[dynamic_plugins]`/`[dynamic_plugin.*]` configuration that failed one
/// of ADR 0025's fail-loud, config-load-time invariants.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DynamicPluginConfigError {
    #[error(
        "dynamic plugin `{0}` is listed in [dynamic_plugins] plugins but has no \
         [dynamic_plugin.{0}] section"
    )]
    MissingSection(String),

    #[error(
        "dynamic plugin name `{0}` collides with a builtin auth method name and \
         cannot be used"
    )]
    ReservedName(String),

    #[error("dynamic plugin `{plugin}` declares unknown capability `{capability}`")]
    UnknownCapability { plugin: String, capability: String },

    #[error(
        "dynamic plugin `{plugin}` is mode `{mode:?}` and cannot be granted capability \
         `{capability}` - provision_user/find_user/assign_role are config-load errors \
         outside full_auth mode"
    )]
    CapabilityNotAllowedInMode {
        plugin: String,
        mode: PluginMode,
        capability: String,
    },

    #[error(
        "dynamic plugin `{0}` is mode full_auth but has neither provision_user nor \
         find_user capability, so it can never produce a valid identity handle and \
         can only ever Deny"
    )]
    FullAuthWithoutIdentityCapability(String),

    #[error(
        "dynamic plugin `{plugin}` grants provision_user/find_user but has neither \
         provision_domain_id nor allowed_provision_domains set"
    )]
    ProvisioningWithoutDomain { plugin: String },

    #[error(
        "dynamic plugin `{plugin}` exposes hard-denylisted header `{header}` via \
         exposed_headers - this header can never be forwarded to a plugin"
    )]
    HardDenylistedHeaderExposed { plugin: String, header: String },

    #[error("dynamic plugin `{0}` is mode route but has an empty inspect_methods list")]
    RouteWithoutInspectMethods(String),

    #[error("dynamic plugin `{0}` is mode route but has an empty route_targets list")]
    RouteWithoutTargets(String),

    #[error(
        "dynamic plugin `{plugin}` route_targets names `{target}`, which is never a \
         valid route target"
    )]
    RouteTargetForbidden { plugin: String, target: String },

    #[error("dynamic plugin `{plugin}` route_targets names itself (`{plugin}`)")]
    RouteTargetSelfReference { plugin: String },

    #[error("dynamic plugin `{0}` sha256 must be 64 lowercase hex characters")]
    MalformedSha256(String),

    #[error(
        "dynamic plugin `{0}` sets inspect_methods and/or route_targets but is not mode \
         route - these fields only take effect in route mode and setting them elsewhere \
         is almost certainly a misconfiguration"
    )]
    RouteFieldsOutsideRouteMode(String),
}

impl DynamicPluginsSection {
    /// Validate the cross-field, config-load-time invariants ADR 0025 §4/§5
    /// describe as fail-loud errors rather than silent no-ops. This does
    /// **not** touch the filesystem (no checksum verification against the
    /// `.wasm` file - that is a load-time, not config-parse-time, concern
    /// per ADR 0025 §5) and does not require a live plugin registry.
    pub fn validate_semantics(
        &self,
        plugins: &HashMap<String, DynamicPluginConfig>,
    ) -> Result<(), DynamicPluginConfigError> {
        for name in &self.plugins {
            let plugin = plugins
                .get(name)
                .ok_or_else(|| DynamicPluginConfigError::MissingSection(name.clone()))?;

            if RESERVED_AUTH_METHOD_NAMES.contains(&name.as_str()) {
                return Err(DynamicPluginConfigError::ReservedName(name.clone()));
            }

            if !plugin.sha256.len().eq(&64)
                || !plugin.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                || plugin.sha256.bytes().any(|b| b.is_ascii_uppercase())
            {
                return Err(DynamicPluginConfigError::MalformedSha256(name.clone()));
            }

            for capability in &plugin.capabilities {
                if !KNOWN_CAPABILITIES.contains(&capability.as_str()) {
                    return Err(DynamicPluginConfigError::UnknownCapability {
                        plugin: name.clone(),
                        capability: capability.clone(),
                    });
                }
            }

            if plugin.mode != PluginMode::Route
                && (!plugin.inspect_methods.is_empty() || !plugin.route_targets.is_empty())
            {
                return Err(DynamicPluginConfigError::RouteFieldsOutsideRouteMode(
                    name.clone(),
                ));
            }

            match plugin.mode {
                PluginMode::FullAuth => {
                    let has_identity_capability = plugin
                        .capabilities
                        .iter()
                        .any(|c| c == "provision_user" || c == "find_user");
                    if !has_identity_capability {
                        return Err(DynamicPluginConfigError::FullAuthWithoutIdentityCapability(
                            name.clone(),
                        ));
                    }
                    let grants_provisioning = plugin
                        .capabilities
                        .iter()
                        .any(|c| c == "provision_user" || c == "find_user");
                    if grants_provisioning
                        && plugin.provision_domain_id.is_none()
                        && plugin.allowed_provision_domains.is_empty()
                    {
                        return Err(DynamicPluginConfigError::ProvisioningWithoutDomain {
                            plugin: name.clone(),
                        });
                    }
                }
                PluginMode::Mapping | PluginMode::Route => {
                    for capability in &plugin.capabilities {
                        if matches!(
                            capability.as_str(),
                            "provision_user" | "find_user" | "assign_role"
                        ) {
                            return Err(DynamicPluginConfigError::CapabilityNotAllowedInMode {
                                plugin: name.clone(),
                                mode: plugin.mode,
                                capability: capability.clone(),
                            });
                        }
                    }
                    if plugin.mode == PluginMode::Route {
                        if plugin.inspect_methods.is_empty() {
                            return Err(DynamicPluginConfigError::RouteWithoutInspectMethods(
                                name.clone(),
                            ));
                        }
                        if plugin.route_targets.is_empty() {
                            return Err(DynamicPluginConfigError::RouteWithoutTargets(
                                name.clone(),
                            ));
                        }
                        for target in &plugin.route_targets {
                            if ROUTE_TARGET_FORBIDDEN_NAMES.contains(&target.as_str()) {
                                return Err(DynamicPluginConfigError::RouteTargetForbidden {
                                    plugin: name.clone(),
                                    target: target.clone(),
                                });
                            }
                            if target == name {
                                return Err(DynamicPluginConfigError::RouteTargetSelfReference {
                                    plugin: name.clone(),
                                });
                            }
                        }
                    }
                }
            }

            for header in &plugin.exposed_headers {
                if HARD_DENYLISTED_HEADERS.contains(&header.to_ascii_lowercase().as_str()) {
                    return Err(DynamicPluginConfigError::HardDenylistedHeaderExposed {
                        plugin: name.clone(),
                        header: header.clone(),
                    });
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use config::{Config, File, FileFormat};

    use super::*;

    fn parse(ini: &str) -> (DynamicPluginsSection, HashMap<String, DynamicPluginConfig>) {
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            #[serde(default)]
            dynamic_plugins: DynamicPluginsSection,
            #[serde(default)]
            dynamic_plugin: HashMap<String, DynamicPluginConfig>,
        }

        let c = Config::builder()
            .add_source(File::from_str(ini, FileFormat::Ini))
            .build()
            .unwrap();
        let wrapper: Wrapper = c.try_deserialize().unwrap();
        (wrapper.dynamic_plugins, wrapper.dynamic_plugin)
    }

    fn valid_full_auth_ini() -> &'static str {
        r#"
[dynamic_plugins]
plugins = acme_risk_sso

[dynamic_plugin.acme_risk_sso]
path = /etc/keystone/plugins/acme_risk_sso.wasm
sha256 = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
mode = full_auth
capabilities = http_fetch,provision_user,find_user
exposed_headers = X-Acme-Session-Id
allowed_hosts = risk.acme.example.com
provision_domain_id = domain_acme_sso
assign_role_allowed = reader,member
"#
    }

    #[test]
    fn test_valid_full_auth_config_parses_and_validates() {
        let (section, plugins) = parse(valid_full_auth_ini());
        assert_eq!(section.plugins, vec!["acme_risk_sso".to_string()]);
        let plugin = plugins.get("acme_risk_sso").unwrap();
        assert_eq!(plugin.mode, PluginMode::FullAuth);
        assert_eq!(plugin.timeout_ms, default_timeout_ms());
        section.validate_semantics(&plugins).unwrap();
    }

    #[test]
    fn test_route_mode_config_parses_and_validates() {
        let ini = r#"
[dynamic_plugins]
plugins = tf_appcred_router

[dynamic_plugin.tf_appcred_router]
path = /etc/keystone/plugins/tf_appcred_router.wasm
sha256 = 3b5d5c3712955042212316173ccf37be9de53d6c84a5c7c8e6e0e5e7f5f8a1bc
mode = route
inspect_methods = application_credential
route_targets = tf_appcred_handler
"#;
        let (section, plugins) = parse(ini);
        section.validate_semantics(&plugins).unwrap();
    }

    #[test]
    fn test_missing_section_is_rejected() {
        let ini = r#"
[dynamic_plugins]
plugins = acme_risk_sso
"#;
        let (section, plugins) = parse(ini);
        assert_eq!(
            section.validate_semantics(&plugins),
            Err(DynamicPluginConfigError::MissingSection(
                "acme_risk_sso".into()
            ))
        );
    }

    #[test]
    fn test_reserved_name_is_rejected() {
        let mut ini = valid_full_auth_ini().replace("acme_risk_sso", "password");
        // Sanity: replacement must have hit both the [dynamic_plugins] list
        // and the section header/name.
        assert!(ini.contains("plugins = password"));
        ini = ini.replace("provision_domain_id = domain_acme_sso", "");
        let (section, plugins) = parse(&ini);
        assert_eq!(
            section.validate_semantics(&plugins),
            Err(DynamicPluginConfigError::ReservedName("password".into()))
        );
    }

    #[test]
    fn test_malformed_sha256_is_rejected() {
        let ini = valid_full_auth_ini().replace(
            "sha256 = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "sha256 = not-a-hash",
        );
        let (section, plugins) = parse(&ini);
        assert_eq!(
            section.validate_semantics(&plugins),
            Err(DynamicPluginConfigError::MalformedSha256(
                "acme_risk_sso".into()
            ))
        );
    }

    #[test]
    fn test_unknown_capability_is_rejected() {
        let ini = valid_full_auth_ini().replace(
            "capabilities = http_fetch,provision_user,find_user",
            "capabilities = http_fetch,provision_user,find_user,mint_token",
        );
        let (section, plugins) = parse(&ini);
        assert_eq!(
            section.validate_semantics(&plugins),
            Err(DynamicPluginConfigError::UnknownCapability {
                plugin: "acme_risk_sso".into(),
                capability: "mint_token".into(),
            })
        );
    }

    #[test]
    fn test_mapping_mode_with_provision_user_is_rejected() {
        let ini = valid_full_auth_ini().replace("mode = full_auth", "mode = mapping");
        let (section, plugins) = parse(&ini);
        assert_eq!(
            section.validate_semantics(&plugins),
            Err(DynamicPluginConfigError::CapabilityNotAllowedInMode {
                plugin: "acme_risk_sso".into(),
                mode: PluginMode::Mapping,
                capability: "provision_user".into(),
            })
        );
    }

    #[test]
    fn test_full_auth_without_identity_capability_is_rejected() {
        let ini = valid_full_auth_ini().replace(
            "capabilities = http_fetch,provision_user,find_user",
            "capabilities = http_fetch",
        );
        let (section, plugins) = parse(&ini);
        assert_eq!(
            section.validate_semantics(&plugins),
            Err(DynamicPluginConfigError::FullAuthWithoutIdentityCapability(
                "acme_risk_sso".into()
            ))
        );
    }

    #[test]
    fn test_provisioning_without_domain_is_rejected() {
        let ini = valid_full_auth_ini().replace("provision_domain_id = domain_acme_sso", "");
        let (section, plugins) = parse(&ini);
        assert_eq!(
            section.validate_semantics(&plugins),
            Err(DynamicPluginConfigError::ProvisioningWithoutDomain {
                plugin: "acme_risk_sso".into(),
            })
        );
    }

    #[test]
    fn test_hard_denylisted_header_is_rejected() {
        let ini = valid_full_auth_ini().replace(
            "exposed_headers = X-Acme-Session-Id",
            "exposed_headers = Authorization",
        );
        let (section, plugins) = parse(&ini);
        assert_eq!(
            section.validate_semantics(&plugins),
            Err(DynamicPluginConfigError::HardDenylistedHeaderExposed {
                plugin: "acme_risk_sso".into(),
                header: "Authorization".into(),
            })
        );
    }

    #[test]
    fn test_route_without_inspect_methods_is_rejected() {
        let ini = r#"
[dynamic_plugins]
plugins = tf_appcred_router

[dynamic_plugin.tf_appcred_router]
path = /etc/keystone/plugins/tf_appcred_router.wasm
sha256 = 3b5d5c3712955042212316173ccf37be9de53d6c84a5c7c8e6e0e5e7f5f8a1bc
mode = route
route_targets = tf_appcred_handler
"#;
        let (section, plugins) = parse(ini);
        assert_eq!(
            section.validate_semantics(&plugins),
            Err(DynamicPluginConfigError::RouteWithoutInspectMethods(
                "tf_appcred_router".into()
            ))
        );
    }

    #[test]
    fn test_route_without_targets_is_rejected() {
        let ini = r#"
[dynamic_plugins]
plugins = tf_appcred_router

[dynamic_plugin.tf_appcred_router]
path = /etc/keystone/plugins/tf_appcred_router.wasm
sha256 = 3b5d5c3712955042212316173ccf37be9de53d6c84a5c7c8e6e0e5e7f5f8a1bc
mode = route
inspect_methods = application_credential
"#;
        let (section, plugins) = parse(ini);
        assert_eq!(
            section.validate_semantics(&plugins),
            Err(DynamicPluginConfigError::RouteWithoutTargets(
                "tf_appcred_router".into()
            ))
        );
    }

    #[test]
    fn test_route_target_forbidden_name_is_rejected() {
        let ini = r#"
[dynamic_plugins]
plugins = tf_appcred_router

[dynamic_plugin.tf_appcred_router]
path = /etc/keystone/plugins/tf_appcred_router.wasm
sha256 = 3b5d5c3712955042212316173ccf37be9de53d6c84a5c7c8e6e0e5e7f5f8a1bc
mode = route
inspect_methods = application_credential
route_targets = admin
"#;
        let (section, plugins) = parse(ini);
        assert_eq!(
            section.validate_semantics(&plugins),
            Err(DynamicPluginConfigError::RouteTargetForbidden {
                plugin: "tf_appcred_router".into(),
                target: "admin".into(),
            })
        );
    }

    #[test]
    fn test_route_target_self_reference_is_rejected() {
        let ini = r#"
[dynamic_plugins]
plugins = tf_appcred_router

[dynamic_plugin.tf_appcred_router]
path = /etc/keystone/plugins/tf_appcred_router.wasm
sha256 = 3b5d5c3712955042212316173ccf37be9de53d6c84a5c7c8e6e0e5e7f5f8a1bc
mode = route
inspect_methods = application_credential
route_targets = tf_appcred_router
"#;
        let (section, plugins) = parse(ini);
        assert_eq!(
            section.validate_semantics(&plugins),
            Err(DynamicPluginConfigError::RouteTargetSelfReference {
                plugin: "tf_appcred_router".into(),
            })
        );
    }

    #[test]
    fn test_route_targets_outside_route_mode_is_rejected() {
        let ini = r#"
[dynamic_plugins]
plugins = acme_risk_sso

[dynamic_plugin.acme_risk_sso]
path = /etc/keystone/plugins/acme_risk_sso.wasm
sha256 = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
mode = full_auth
capabilities = provision_user
provision_domain_id = domain_acme_sso
route_targets = password
"#;
        let (section, plugins) = parse(ini);
        assert_eq!(
            section.validate_semantics(&plugins),
            Err(DynamicPluginConfigError::RouteFieldsOutsideRouteMode(
                "acme_risk_sso".into()
            ))
        );
    }

    #[test]
    fn test_inspect_methods_outside_route_mode_is_rejected() {
        let ini = r#"
[dynamic_plugins]
plugins = acme_risk_sso

[dynamic_plugin.acme_risk_sso]
path = /etc/keystone/plugins/acme_risk_sso.wasm
sha256 = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
mode = mapping
inspect_methods = password
"#;
        let (section, plugins) = parse(ini);
        assert_eq!(
            section.validate_semantics(&plugins),
            Err(DynamicPluginConfigError::RouteFieldsOutsideRouteMode(
                "acme_risk_sso".into()
            ))
        );
    }
}
