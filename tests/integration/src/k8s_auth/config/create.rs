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

#[traced_test]
#[tokio::test]
async fn test_create() -> Result<()> {
    let state = get_state().await?;
    let sot = K8sAuthConfigurationCreate {
        ca_cert: Some("ca".into()),
        disable_local_ca_jwt: Some(true),
        domain_id: "domain_a".into(),
        enabled: true,
        host: "host".into(),
        id: Some(uuid::Uuid::new_v4().simple().to_string()),
        name: Some(uuid::Uuid::new_v4().to_string()),
    };
    let res = state
        .provider
        .get_k8s_auth_provider()
        .create_k8s_auth_configuration(&state, sot.clone())
        .await?;
    assert_eq!(sot.name, res.name);
    assert_eq!(sot.id.unwrap(), res.id);
    assert_eq!(sot.ca_cert, res.ca_cert);
    assert_eq!(sot.enabled, res.enabled);
    assert_eq!(sot.host, res.host);

    state
        .provider
        .get_k8s_auth_provider()
        .delete_k8s_auth_configuration(&state, &res.id)
        .await?;
    Ok(())
}
