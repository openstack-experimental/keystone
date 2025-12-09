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
//! Test add user group membership functionality.

use eyre::Report;
use tracing_test::traced_test;

use openstack_keystone::identity::IdentityApi;

use super::*;

#[tokio::test]
#[traced_test]
async fn test_expiring_groups() -> Result<(), Report> {
    let state = get_state().await?;

    state
        .provider
        .get_identity_provider()
        .add_user_to_group_expiring(&state, "user_a", "group_b", "idp_id")
        .await?;

    assert_eq!(
        list_user_groups(&state, "user_a")
            .await?
            .into_iter()
            .map(|group| group.id.clone())
            .collect::<Vec<_>>(),
        vec!["group_a".to_string(), "group_b".to_string()],
        "user is member of groups a and b"
    );
    Ok(())
}
