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
async fn test_get_config() -> Result<()> {
    let state = get_state().await?;

    let k8s_conf = create_k8s_auth_configuration(
        &state,
        K8sAuthConfigurationCreate {
            ca_cert: Some("ca".into()),
            domain_id: "domain_a".into(),
            enabled: true,
            host: "host".into(),
            id: None,
            name: Some(uuid::Uuid::new_v4().to_string()),
        },
    )
    .await?;

    let res = state
        .provider
        .get_k8s_auth_provider()
        .get_k8s_auth_configuration(&state, &k8s_conf.id)
        .await?
        .expect("config should be there");
    assert_eq!(res.id, k8s_conf.id);
    assert_eq!(res.name, k8s_conf.name);
    assert_eq!(res.ca_cert, k8s_conf.ca_cert);
    assert_eq!(res.host, k8s_conf.host);
    assert_eq!(res.enabled, k8s_conf.enabled);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_config_missing() -> Result<()> {
    let state = get_state().await?;

    assert!(
        state
            .provider
            .get_k8s_auth_provider()
            .get_k8s_auth_configuration(&state, &uuid::Uuid::new_v4().to_string())
            .await?
            .is_none()
    );
    Ok(())
}
