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
//! Test k8s auth config.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone::k8s_auth::{K8sAuthApi, types::*};

use super::super::config::create_k8s_auth_configuration;
use super::super::get_state;
use super::super::role::create_k8s_auth_role;
use crate::token::token_restriction::create_token_restriction;

#[traced_test]
#[tokio::test]
async fn test_update() -> Result<()> {
    let state = get_state().await?;

    let k8s_conf = create_k8s_auth_configuration(
        &state,
        K8sAuthConfigurationCreate {
            ca_cert: Some("ca".into()),
            disable_local_ca_jwt: Some(false),
            domain_id: "domain_a".into(),
            enabled: true,
            host: "host".into(),
            id: None,
            name: Some(uuid::Uuid::new_v4().to_string()),
        },
    )
    .await?;
    let tr = create_token_restriction(
        &state,
        openstack_keystone::token::TokenRestrictionCreate {
            allow_rescope: false,
            allow_renew: false,
            id: String::new(),
            domain_id: "domain_a".into(),
            project_id: None,
            role_ids: Vec::new(),
            user_id: None,
        },
    )
    .await?;
    let k8s_role = create_k8s_auth_role(
        &state,
        K8sAuthRoleCreate {
            auth_configuration_id: k8s_conf.id.clone(),
            bound_audience: Some("aud".into()),
            bound_service_account_names: vec!["a".into(), "b".into()],
            bound_service_account_namespaces: vec!["na".into(), "nb".into()],
            domain_id: "domain_a".into(),
            enabled: false,
            id: None,
            name: uuid::Uuid::new_v4().to_string(),
            token_restriction_id: tr.id.clone(),
        },
    )
    .await?;

    let req = K8sAuthRoleUpdate {
        bound_audience: Some("new_aud".into()),
        bound_service_account_names: Some(vec!["c".into()]),
        bound_service_account_namespaces: Some(vec!["nc".into()]),
        enabled: Some(true),
        name: Some("new_name".into()),
        token_restriction_id: Some(tr.id.clone()),
    };

    let res = state
        .provider
        .get_k8s_auth_provider()
        .update_k8s_auth_role(&state, &k8s_role.id, req)
        .await?;

    assert_eq!(k8s_role.id, res.id);
    assert_eq!(Some("new_aud"), res.bound_audience.as_deref());
    assert_eq!(vec!["c".to_string()], res.bound_service_account_names);
    assert_eq!(vec!["nc".to_string()], res.bound_service_account_namespaces);
    assert!(res.enabled);
    assert_eq!("new_name", res.name);
    assert_eq!(tr.id, res.token_restriction_id);

    Ok(())
}
