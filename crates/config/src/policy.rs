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
use serde::{Deserialize, Deserializer};
use std::path::PathBuf;
use url::Url;
use url_macro::url;

/// Configuration of the Open Policy Agent engine (`engine = "opa"`).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct OpaConfig {
    /// OpenPolicyAgent instance url to use for evaluating the policy
    /// (`opa_base_url`).
    #[serde(rename = "opa_base_url", default = "default_opa_base_url")]
    pub base_url: Url,

    /// Path to the policies to trigger starting OPA as a subprocess
    /// (`opa_policies_path`). When set OPA would be started as `opa run -s
    /// <policies_path> --addr <base_url>`. The OPA binary must be in the PATH
    /// for this to work.
    #[serde(rename = "opa_policies_path", default)]
    pub policies_path: Option<PathBuf>,
}

impl Default for OpaConfig {
    fn default() -> Self {
        Self {
            base_url: default_opa_base_url(),
            policies_path: None,
        }
    }
}

/// Configuration of the in-process `regorus` engine (`engine = "regorus"`).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct RegorusConfig {
    /// Directory with the Rego policies (`regorus_policies_path`). The
    /// directory is the same `policy/` tree OPA consumes (`*_test.rego` files
    /// are ignored). Keystone reloads it on `SIGHUP`.
    #[serde(rename = "regorus_policies_path")]
    pub policies_path: PathBuf,
}

/// The policy engine used to evaluate the API policies together with its own
/// options (`[api_policy]`).
///
/// `engine` selects the kind and the engine specific options carry the engine
/// name as prefix. A missing `engine` (or an absent section) selects OPA, see
/// [`deserialize_or_default_opa`].
///
/// ```ini
/// [api_policy]
/// engine = opa
/// opa_base_url = http://localhost:8181
/// opa_policies_path = /policy
///
/// ; or
/// engine = regorus
/// regorus_policies_path = /policy
/// ```
///
/// Options of the engine that is not selected are ignored.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "engine", rename_all = "lowercase")]
pub enum PolicyEngine {
    /// Open Policy Agent reached over HTTP or a unix socket (the default).
    Opa(OpaConfig),
    /// Rego evaluated in-process by `regorus`. Requires the `regorus` cargo
    /// feature of the `keystone` binary.
    Regorus(RegorusConfig),
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::Opa(OpaConfig::default())
    }
}

/// Deserialize `[api_policy]`, selecting OPA when `engine` is not set.
///
/// serde cannot default the tag of an internally tagged enum, so it is
/// inserted here. Meant for `#[serde(deserialize_with = ...)]`.
pub fn deserialize_or_default_opa<'de, D>(deserializer: D) -> Result<PolicyEngine, D::Error>
where
    D: Deserializer<'de>,
{
    let mut section = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
    section
        .entry("engine")
        .or_insert_with(|| serde_json::Value::String("opa".into()));
    PolicyEngine::deserialize(serde_json::Value::Object(section)).map_err(serde::de::Error::custom)
}

fn default_opa_base_url() -> Url {
    url!("http://localhost:8181")
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{Config as RawConfig, File, FileFormat};

    #[derive(Deserialize)]
    struct Wrapper {
        #[serde(default, deserialize_with = "deserialize_or_default_opa")]
        api_policy: PolicyEngine,
    }

    fn parse(ini: &str) -> Result<PolicyEngine, config::ConfigError> {
        let ini = format!("[api_policy]\n{ini}");
        Ok(RawConfig::builder()
            .add_source(File::from_str(&ini, FileFormat::Ini))
            .build()?
            .try_deserialize::<Wrapper>()?
            .api_policy)
    }

    #[test]
    fn default_is_opa() {
        assert_eq!(
            PolicyEngine::default(),
            PolicyEngine::Opa(OpaConfig::default())
        );
    }

    #[test]
    fn opa_defaults() {
        let cfg = parse("engine = opa\n").unwrap();
        assert_eq!(cfg, PolicyEngine::Opa(OpaConfig::default()));
    }

    #[test]
    fn opa_options() {
        let cfg =
            parse("engine = opa\nopa_base_url = http://opa:1/\nopa_policies_path = /p\n").unwrap();
        assert_eq!(
            cfg,
            PolicyEngine::Opa(OpaConfig {
                base_url: Url::parse("http://opa:1/").unwrap(),
                policies_path: Some("/p".into()),
            })
        );
    }

    #[test]
    fn regorus_options() {
        let cfg = parse("engine = regorus\nregorus_policies_path = /p\n").unwrap();
        assert_eq!(
            cfg,
            PolicyEngine::Regorus(RegorusConfig {
                policies_path: "/p".into()
            })
        );
    }

    #[test]
    fn regorus_requires_path() {
        assert!(parse("engine = regorus\n").is_err());
    }

    #[test]
    fn missing_engine_is_opa() {
        let cfg = parse("opa_base_url = http://x/\n").unwrap();
        assert_eq!(
            cfg,
            PolicyEngine::Opa(OpaConfig {
                base_url: Url::parse("http://x/").unwrap(),
                policies_path: None,
            })
        );
    }

    #[test]
    fn unknown_engine_is_rejected() {
        assert!(parse("engine = nope\n").is_err());
    }

    #[test]
    fn regorus_ignores_opa_options() {
        let cfg = parse("engine = regorus\nregorus_policies_path = /p\nopa_base_url = http://x/\n")
            .unwrap();
        assert!(matches!(cfg, PolicyEngine::Regorus(_)));
    }
}
