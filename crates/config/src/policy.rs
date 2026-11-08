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
use serde::Deserialize;
use std::path::PathBuf;
use url::Url;
use url_macro::url;

/// The policy engine used to evaluate the API policies.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEngine {
    /// Open Policy Agent reached over HTTP or a unix socket (the default).
    #[default]
    Opa,
    /// Rego evaluated in-process by `regorus`. Requires the `regorus` cargo
    /// feature of the `keystone` binary and `regorus_policies_path`.
    Regorus,
}

/// The configuration options for the API policy enforcement.
#[derive(Clone, Debug, Deserialize)]
pub struct PolicyProvider {
    /// The policy engine evaluating the Rego policies.
    #[serde(default)]
    pub engine: PolicyEngine,

    /// Directory with the Rego policies evaluated in-process when
    /// `engine = "regorus"`. The directory is the same `policy/` tree OPA
    /// consumes (`*_test.rego` files are ignored).
    pub regorus_policies_path: Option<PathBuf>,

    /// OpenPolicyAgent instance url to use for evaluating the policy.
    #[serde(default = "default_opa_base_url")]
    pub opa_base_url: Url,

    /// Path to the policies to trigger starting OPA as a subprocess. When set
    /// OPA would be started as `opa run -s <OPA_POLICIES_PATH> --addr
    /// OPA_BASE_URL`. The OPA binary must be in the PATH for this to work.
    pub opa_policies_path: Option<PathBuf>,
}

impl Default for PolicyProvider {
    fn default() -> Self {
        Self {
            engine: PolicyEngine::default(),
            regorus_policies_path: None,
            opa_base_url: default_opa_base_url(),
            opa_policies_path: None,
        }
    }
}

fn default_opa_base_url() -> Url {
    url!("http://localhost:8181")
}
