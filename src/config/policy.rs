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
use url::Url;
use url_macro::url;

use super::common::default_true;

/// The configuration options for the API policy enforcement.
#[derive(Clone, Debug, Deserialize)]
pub struct PolicyProvider {
    /// Whether the policy enforcement should be enforced or not.
    #[serde(default = "default_true")]
    pub enable: bool,

    /// OpenPolicyAgent instance url to use for evaluating the policy.
    #[serde(default = "default_opa_base_url")]
    pub opa_base_url: Url,
}

impl Default for PolicyProvider {
    fn default() -> Self {
        Self {
            enable: true,
            opa_base_url: default_opa_base_url(),
        }
    }
}

fn default_opa_base_url() -> Url {
    url!("http://localhost:8181")
}
