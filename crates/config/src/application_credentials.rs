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

use crate::common::default_sql_driver;

/// Application Credential Provider.
#[derive(Debug, Deserialize, Clone)]
pub struct ApplicationCredentialProvider {
    /// Application credentials provider driver.
    #[serde(default = "default_sql_driver")]
    pub driver: String,

    /// When `true`, refuse to create an application credential carrying a
    /// non-empty `access_rules` list instead of silently accepting it.
    ///
    /// `access_rules` (per-endpoint restrictions) are stored and CRUD'd but
    /// **not enforced at request time** -- no middleware matches the
    /// incoming (service, method, path) against them yet (security review
    /// V5, `doc/src/security.md` §5/§9). Until that enforcement lands, a
    /// non-empty `access_rules` list is a restriction the operator believes
    /// is active but is actually a no-op. Defaults to `false` to preserve
    /// existing behavior (a warning is logged either way); set `true` to
    /// fail loud instead.
    #[serde(default)]
    pub reject_unenforced_access_rules: bool,
}

impl Default for ApplicationCredentialProvider {
    fn default() -> Self {
        Self {
            driver: default_sql_driver(),
            reject_unenforced_access_rules: false,
        }
    }
}
