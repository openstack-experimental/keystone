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
//! Cross-realm & manual-user membership fencing (ADR 0024 §7).

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::scim::ScimResourceType;

use crate::keystone::ServiceState;
use crate::scim::error::ScimApiError;

/// Reject a `members` list containing any `User.id` not owned by this same
/// realm — a reference to a user owned by a different realm, or to a
/// manually-created user with no `ScimResourceIndex` entry at all, is a
/// `400 Bad Request` (`scimType: "invalidValue"`), not a silent no-op or a
/// cross-realm existence leak.
pub(super) async fn validate_members_owned_by_realm(
    state: &ServiceState,
    exec: &ExecutionContext<'_>,
    domain_id: &str,
    provider_id: &str,
    member_ids: &[String],
) -> Result<(), ScimApiError> {
    for member_id in member_ids {
        let owned = state
            .provider
            .get_scim_resource_provider()
            .get_index(
                exec,
                domain_id,
                provider_id,
                ScimResourceType::User,
                member_id,
            )
            .await?
            .is_some_and(|i| i.deprovisioned_at.is_none());
        if !owned {
            return Err(ScimApiError::InvalidValue(format!(
                "member {member_id} is not a user owned by this realm"
            )));
        }
    }
    Ok(())
}
