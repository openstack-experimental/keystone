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

//! Group membership API (`/v3/groups/{group_id}/users`).

use serde_json::{Value, json};
use utoipa_axum::{router::OpenApiRouter, routes};

use openstack_keystone_core::auth::{ExecutionContext, ValidatedSecurityContext};

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

mod add;
mod check;
mod list;
mod remove;

/// OpenAPI router for the group membership.
///
/// Routes:
/// - `GET /groups/{group_id}/users` - list users in the group
/// - `HEAD /groups/{group_id}/users/{user_id}` - check the membership
/// - `PUT /groups/{group_id}/users/{user_id}` - add the user to the group
/// - `DELETE /groups/{group_id}/users/{user_id}` - remove the user from the
///   group
pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list))
        .routes(routes!(check::check))
        .routes(routes!(add::add))
        .routes(routes!(remove::remove))
}

/// Load the group and the user of a membership operation.
///
/// Both are returned as the policy `existing` document (`null` members for
/// missing objects) so the policy is always evaluated before the 404 is
/// reported (security model I10).
///
/// # Returns
/// The `existing` policy document and the presence flags (`group`, `user`).
async fn load_membership(
    state: &ServiceState,
    user_auth: &ValidatedSecurityContext,
    group_id: &str,
    user_id: &str,
) -> Result<(Value, bool, bool), KeystoneApiError> {
    let ctx = ExecutionContext::from_auth(state, user_auth);
    let identity = state.provider.get_identity_provider();
    let group = identity.get_group(&ctx, group_id).await?;
    let user = identity.get_user(&ctx, user_id).await?;
    Ok((
        json!({"group": group, "user": user}),
        group.is_some(),
        user.is_some(),
    ))
}

/// Report which of the membership objects is missing.
fn not_found(group_found: bool, group_id: &str, user_id: &str) -> KeystoneApiError {
    if group_found {
        KeystoneApiError::NotFound {
            resource: "user".into(),
            identifier: user_id.into(),
        }
    } else {
        KeystoneApiError::NotFound {
            resource: "group".into(),
            identifier: group_id.into(),
        }
    }
}

#[cfg(test)]
mod tests {}
