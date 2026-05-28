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

use std::collections::HashMap;
use std::sync::Arc;

use eyre::Result;
use uuid::Uuid;

use openstack_keystone_api_types::{
    v3::project::ProjectCreateBuilder, v4::spiffe::binding::SpiffeAuthorization,
};
use openstack_sdk::AsyncOpenStack;
use openstack_sdk::config::CloudConfig;

use super::*;
use crate::guard::*;
use crate::resource::project::*;
use crate::role::list_roles;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_spiffe_binding_crud() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let svid = format!(
        "spiffe://example.org/ns/default/sa/{}",
        Uuid::new_v4().simple()
    );

    let binding = create_binding(
        &test_client,
        SpiffeBindingCreate {
            domain_id: "default".to_string(),
            is_system: false,
            svid: svid.clone(),
            user_id: None,
            authorizations: None,
        },
    )
    .await?;

    assert_eq!(binding.svid, svid);
    assert_eq!(binding.domain_id, "default");
    assert!(!binding.is_system);
    assert!(binding.user_id.is_none());
    assert!(binding.authorizations.is_none());

    let shown = show_binding(&test_client, &svid).await?;
    assert_eq!(shown.svid, binding.svid);
    assert_eq!(shown.domain_id, binding.domain_id);

    let project = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .parent_id("default")
            .name(Uuid::new_v4().simple().to_string())
            .is_domain(false)
            .enabled(true)
            .build()?,
    )
    .await?;

    let roles: HashMap<String, String> = list_roles(&test_client)
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let member_role = roles.get("member").expect("member role must exist");

    let updated = update_binding(
        &test_client,
        &svid,
        openstack_keystone_api_types::v4::spiffe::binding::SpiffeBindingUpdate {
            authorizations: Some(vec![SpiffeAuthorization::Project {
                project_id: project.id.clone(),
                role_ids: Some(vec![member_role.clone()]),
            }]),
        },
    )
    .await?;

    let updated_authorizations = updated
        .authorizations
        .expect("authorizations should be set after update");
    assert_eq!(updated_authorizations.len(), 1);

    let listed = list_bindings(&test_client).await?;
    assert!(listed.iter().any(|b| b.svid == svid));

    binding.delete().await?;

    let listed_after_delete = list_bindings(&test_client).await?;
    assert!(!listed_after_delete.iter().any(|b| b.svid == svid));

    Ok(())
}
