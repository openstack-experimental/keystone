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

use super::super::get_state;
use super::create_k8s_auth_configuration;

#[traced_test]
#[tokio::test]
async fn test_update() -> Result<()> {
    let state = get_state().await?;

    let sot = K8sAuthConfigurationCreate {
        ca_cert: Some("ca".into()),
        domain_id: "domain_a".into(),
        enabled: false,
        host: "host".into(),
        id: None,
        name: Some(uuid::Uuid::new_v4().to_string()),
    };
    let k8s_conf = create_k8s_auth_configuration(&state, sot.clone()).await?;

    let req = K8sAuthConfigurationUpdate {
        ca_cert: Some("new_ca".into()),
        enabled: Some(true),
        host: Some("new_host".into()),
        name: Some("new_name".into()),
    };
    let res = state
        .provider
        .get_k8s_auth_provider()
        .update_k8s_auth_configuration(&state, &k8s_conf.id, req)
        .await?;
    assert_eq!(k8s_conf.id, res.id);
    assert_eq!(Some("new_name".into()), res.name);
    assert_eq!(Some("new_ca".into()), res.ca_cert);
    assert_eq!("new_host", res.host);
    assert!(res.enabled);

    Ok(())
}
