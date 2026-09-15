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
    /// Historical note: this flag predates request-time enforcement of
    /// `access_rules`, back when a non-empty list was a restriction the
    /// operator believed was active but was actually a no-op (security
    /// review V5). Enforcement now exists (ADR 0037,
    /// `crates/core/src/api/auth.rs`'s `enforce_access_rules`, called
    /// unconditionally from `Auth::from_request_parts` regardless of this
    /// flag) -- `access_rules` is no longer unenforced, so this flag no
    /// longer changes whether the restriction is honored, only whether
    /// *creation* itself is additionally gated. Kept for backward
    /// compatibility of the create-time API; defaults to `false` (a warning
    /// is still logged either way).
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
