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

use std::collections::HashSet;
use std::sync::Arc;

use eyre::Result;
use tracing_test::traced_test;

use openstack_sdk_core::{AsyncOpenStack, config::CloudConfig};

use super::*;
use crate::role::list_roles;

#[tokio::test]
#[traced_test]
async fn test_check_auth_roles() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let auth_token = test_client
        .get_auth_info()
        .expect("must be authenticated")
        .token;
    let all_role_ids: HashSet<String> = list_roles(&test_client)
        .await?
        .into_iter()
        .map(|r| r.id)
        .collect();
    let user_role_ids: HashSet<String> = auth_token
        .roles
        .as_ref()
        .expect("roles must exist")
        .iter()
        .map(|r| r.id.clone())
        .collect();
    for role_id in user_role_ids.union(&all_role_ids) {
        let res = check_grant(
            &test_client,
            &auth_token
                .project
                .as_ref()
                .expect("must be project scope")
                .id
                .as_ref()
                .expect("project must specify id"),
            &auth_token.user.id,
            &role_id,
        )
        .await?;
        if user_role_ids.contains(role_id) {
            assert!(res);
        } else {
            assert!(
                !res,
                "role_id {} is not granted to the user {:?}",
                role_id, auth_token
            );
        }
    }
    Ok(())
}
