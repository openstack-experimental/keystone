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
//! `meta.location` URL construction (RFC 7644 §3.1).

use url::Url;

use crate::keystone::ServiceState;

/// Builds the absolute `meta.location` URL from a base endpoint, mirroring
/// [`crate::api::common::build_pagination_links`]'s
/// fallback-to-`http://localhost` behavior when `public_endpoint` isn't
/// configured.
pub(crate) fn scim_location(
    base: &Url,
    domain_id: &str,
    resource_segment: &str,
    id: &str,
) -> String {
    format!(
        "{}/SCIM/v2/{domain_id}/{resource_segment}/{id}",
        base.as_str().trim_end_matches('/'),
    )
}

/// Reads the configured `public_endpoint` and builds the absolute
/// `meta.location` URL for a resource. `resource_segment` is the plural
/// collection path segment (`"Users"`/`"Groups"`).
pub(crate) async fn resource_location(
    state: &ServiceState,
    domain_id: &str,
    resource_segment: &str,
    id: &str,
) -> String {
    let config = state.config_manager.config.read().await;
    let base = config
        .default
        .public_endpoint
        .clone()
        .unwrap_or_else(|| Url::parse("http://localhost").expect("static URL is valid"));
    scim_location(&base, domain_id, resource_segment, id)
}
