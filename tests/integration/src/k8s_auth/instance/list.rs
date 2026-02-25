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
use super::create_k8s_auth_instance;

#[traced_test]
#[tokio::test]
async fn test_list() -> Result<()> {
    let state = get_state().await?;

    let k8s_conf = create_k8s_auth_instance(
        &state,
        K8sAuthInstanceCreate {
            ca_cert: Some("ca".into()),
            disable_local_ca_jwt: Some(true),
            domain_id: "domain_a".into(),
            enabled: true,
            host: "host".into(),
            id: None,
            name: Some(uuid::Uuid::new_v4().to_string()),
        },
    )
    .await?;
    let k8s_conf2 = create_k8s_auth_instance(
        &state,
        K8sAuthInstanceCreate {
            ca_cert: Some("ca".into()),
            disable_local_ca_jwt: Some(true),
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
        .list_auth_instances(&state, &K8sAuthInstanceListParameters::default())
        .await?;
    assert!(res.contains(&k8s_conf));
    assert!(res.contains(&k8s_conf2));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_name() -> Result<()> {
    let state = get_state().await?;

    let k8s_conf = create_k8s_auth_instance(
        &state,
        K8sAuthInstanceCreate {
            ca_cert: Some("ca".into()),
            disable_local_ca_jwt: Some(true),
            domain_id: "domain_a".into(),
            enabled: true,
            host: "host".into(),
            id: None,
            name: Some(uuid::Uuid::new_v4().to_string()),
        },
    )
    .await?;
    let k8s_conf2 = create_k8s_auth_instance(
        &state,
        K8sAuthInstanceCreate {
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
    let res = state
        .provider
        .get_k8s_auth_provider()
        .list_auth_instances(
            &state,
            &K8sAuthInstanceListParameters {
                name: k8s_conf.name.clone(),
                ..Default::default()
            },
        )
        .await?;
    assert!(res.contains(&k8s_conf));
    assert!(!res.contains(&k8s_conf2));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_domain() -> Result<()> {
    let state = get_state().await?;

    let k8s_conf = create_k8s_auth_instance(
        &state,
        K8sAuthInstanceCreate {
            ca_cert: Some("ca".into()),
            disable_local_ca_jwt: Some(true),
            domain_id: "domain_a".into(),
            enabled: true,
            host: "host".into(),
            id: None,
            name: Some(uuid::Uuid::new_v4().to_string()),
        },
    )
    .await?;
    let k8s_conf2 = create_k8s_auth_instance(
        &state,
        K8sAuthInstanceCreate {
            ca_cert: Some("ca".into()),
            disable_local_ca_jwt: Some(true),
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
        .list_auth_instances(
            &state,
            &K8sAuthInstanceListParameters {
                domain_id: Some("domain_a".into()),
                ..Default::default()
            },
        )
        .await?;
    assert!(res.contains(&k8s_conf));
    assert!(res.contains(&k8s_conf2));
    Ok(())
}
