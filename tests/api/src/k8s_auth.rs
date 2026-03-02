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
//! Test the k8s auth functionality

use std::sync::Arc;

use eyre::{Result, eyre};
use secrecy::SecretString;
use tokio::fs;
use uuid::Uuid;

use openstack_sdk_core::config::CloudConfig;
use openstack_sdk_core::{AsyncOpenStack, api::RawQueryAsync};

use openstack_keystone_api_types::k8s_auth::role::*;
use openstack_keystone_api_types::k8s_auth::{K8sAuthRequest, instance::*};
use openstack_keystone_api_types::v3::project::*;
use openstack_keystone_api_types::v3::user::*;
use openstack_keystone_api_types::v4::auth::token::*;
use openstack_keystone_api_types::v4::token_restriction::*;

mod guard;
use guard::*;
mod identity;
mod resource;
mod token_restriction;

mod k8s_auth {
    pub(super) mod auth;
    pub(super) mod instance;
    pub(super) mod role;
}

use crate::identity::user::create_user;
use crate::k8s_auth::auth::*;
use crate::k8s_auth::instance::create_auth_instance;
use crate::k8s_auth::role::create_auth_role;
use crate::resource::project::create_project;
use crate::token_restriction::create_token_restriction;

async fn auth<I: AsRef<str>>(
    client: &Arc<AsyncOpenStack>,
    instance_id: I,
    obj: K8sAuthRequest,
) -> Result<(Token, SecretString)> {
    let rsp: http::Response<bytes::Bytes> = K8sAuthenticationRequestBuilder::default()
        .instance_id(instance_id.as_ref())
        .auth(obj)
        .build()?
        .raw_query_async(client.as_ref())
        .await?;

    if rsp.status() != http::StatusCode::OK {
        return Err(eyre!("Authentication failed with {}", rsp.status()));
    }

    let token = SecretString::from(
        rsp.headers()
            .get("X-Subject-Token")
            .ok_or_else(|| eyre!("Token is missing in the {:?}", rsp))?
            .to_str()?,
    );
    let token_info: TokenResponse = serde_json::from_slice(rsp.body())?;
    Ok((token_info.token, token))
}

#[tokio::test]
async fn test_k8s_auth() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let user = create_user(
        &test_client,
        UserCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .domain_id("default")
            .enabled(true)
            .build()?,
    )
    .await?;

    let project_create = ProjectCreateBuilder::default()
        .domain_id("default")
        .name(Uuid::new_v4().simple().to_string())
        .build()?;
    let project = create_project(&test_client, project_create).await?;

    let tr = create_token_restriction(
        &test_client,
        TokenRestrictionCreate {
            allow_renew: false,
            allow_rescope: false,
            domain_id: "default".into(),
            project_id: Some(project.id.clone()),
            user_id: Some(user.id.clone()),
            roles: vec![],
        },
    )
    .await?;

    let k8s_ca = fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt").await?;
    let instance = create_auth_instance(
        &test_client,
        K8sAuthInstanceCreate {
            ca_cert: Some(k8s_ca),
            disable_local_ca_jwt: Some(true),
            domain_id: "default".into(),
            enabled: true,
            host: "https://kubernetes.default.svc".into(),
            name: Some(uuid::Uuid::new_v4().simple().to_string()),
        },
    )
    .await?;
    let k8s_role = create_auth_role(
        &test_client,
        K8sAuthRoleCreate {
            bound_audience: None,
            bound_service_account_names: vec![],
            bound_service_account_namespaces: vec![],
            enabled: true,
            name: uuid::Uuid::new_v4().simple().to_string(),
            token_restriction_id: tr.id.clone(),
        },
        &instance.id,
    )
    .await?;

    // Now read the (hopefully not expired) K8 token
    let k8s_token =
        fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token").await?;

    let auth_data = K8sAuthRequest {
        jwt: SecretString::from(k8s_token),
        role_name: k8s_role.name.clone(),
    };
    let (token_data, _token_secret) = auth(&test_client, &instance.id, auth_data).await?;
    //
    assert_eq!(token_data.user.id, user.id);
    assert_eq!(
        token_data.project.expect("must be project scope").id,
        project.id
    );

    tr.delete().await?;
    k8s_role.delete().await?;
    instance.delete().await?;
    project.delete().await?;
    user.delete().await?;
    Ok(())
}
