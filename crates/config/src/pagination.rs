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
//! Per-provider list-pagination limits, mirroring python-keystone's
//! per-resource `list_limit` config plus a global `[DEFAULT] list_limit` /
//! `max_db_limit` fallback (see `keystone.common.driver_hints.Hints`).
use serde::Deserialize;

/// Reusable per-provider pagination limit configuration.
///
/// Embedded as a field in each domain's provider config section (e.g.
/// `IdentityProvider.list_limit`), rather than duplicated inline, so every
/// domain gets the same two knobs.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct ListLimitConfig {
    /// Default page size applied when the client omits `limit`. Falls back
    /// to the global `[DEFAULT] list_limit` when unset.
    pub list_limit: Option<u64>,
    /// Absolute cap a client-supplied `limit` is clamped to. Falls back to
    /// the global `[DEFAULT] max_db_limit` when unset.
    pub max_list_limit: Option<u64>,
}
