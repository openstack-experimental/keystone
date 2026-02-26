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

use eyre::{Result, eyre};
use reqwest::StatusCode;
use secrecy::SecretString;
use tokio::fs;
use uuid::Uuid;

use openstack_keystone_api_types::k8s_auth::auth::*;
use openstack_keystone_api_types::k8s_auth::instance::*;
use openstack_keystone_api_types::k8s_auth::role::*;
use openstack_keystone_api_types::v3::project::*;
use openstack_keystone_api_types::v3::user::{User, UserCreate, UserCreateRequest, UserResponse};
use openstack_keystone_api_types::v4::auth::token::{Token, TokenResponse};
use openstack_keystone_api_types::v4::token_restriction::*;

mod common;

use crate::common::TestClient;

/// Create user
pub async fn create_user(tc: &TestClient, user: UserCreate) -> Result<User> {
    Ok(tc
        .client
        .post(tc.base_url.join("v3/users")?)
        .json(&serde_json::to_value(UserCreateRequest { user })?)
        .send()
        .await?
        .json::<UserResponse>()
        .await?
        .user)
}

pub async fn delete_user<U: AsRef<str>>(tc: &TestClient, user_id: U) -> Result<()> {
    let _ = tc
        .client
        .delete(tc.base_url.join("v3/users/")?.join(user_id.as_ref())?)
        .send()
        .await?;
    Ok(())
}

pub async fn create_project(tc: &TestClient, obj: ProjectCreate) -> Result<Project> {
    Ok(tc
        .client
        .post(tc.base_url.join("v3/projects")?)
        .json(&serde_json::to_value(ProjectCreateRequest {
            project: obj,
        })?)
        .send()
        .await?
        .json::<ProjectResponse>()
        .await?
        .project)
}

pub async fn delete_project<U: AsRef<str>>(tc: &TestClient, id: U) -> Result<()> {
    let _ = tc
        .client
        .delete(tc.base_url.join("v3/projects/")?.join(id.as_ref())?)
        .send()
        .await?;
    Ok(())
}

pub async fn create_auth_instance(
    tc: &TestClient,
    obj: K8sAuthInstanceCreate,
) -> Result<K8sAuthInstance> {
    Ok(tc
        .client
        .post(tc.base_url.join("v4/k8s_auth/instances")?)
        .json(&serde_json::to_value(K8sAuthInstanceCreateRequest {
            instance: obj,
        })?)
        .send()
        .await?
        .json::<K8sAuthInstanceResponse>()
        .await?
        .instance)
}

pub async fn delete_auth_instance<U: AsRef<str>>(tc: &TestClient, id: U) -> Result<()> {
    let _ = tc
        .client
        .delete(
            tc.base_url
                .join("v4/k8s_auth/instances/")?
                .join(id.as_ref())?,
        )
        .send()
        .await?;
    Ok(())
}

pub async fn create_auth_role<I: AsRef<str>>(
    tc: &TestClient,
    instance_id: I,
    obj: K8sAuthRoleCreate,
) -> Result<K8sAuthRole> {
    Ok(tc
        .client
        .post(
            tc.base_url
                .join(format!("v4/k8s_auth/instances/{}/roles", instance_id.as_ref()).as_str())?,
        )
        .json(&serde_json::to_value(K8sAuthRoleCreateRequest {
            role: obj,
        })?)
        .send()
        .await?
        .json::<K8sAuthRoleResponse>()
        .await?
        .role)
}

pub async fn delete_auth_role<U: AsRef<str>>(tc: &TestClient, id: U) -> Result<()> {
    let _ = tc
        .client
        .delete(tc.base_url.join("v4/k8s_auth/roles/")?.join(id.as_ref())?)
        .send()
        .await?;
    Ok(())
}

pub async fn create_token_restriction(
    tc: &TestClient,
    obj: TokenRestrictionCreate,
) -> Result<TokenRestriction> {
    Ok(tc
        .client
        .post(tc.base_url.join("v4/tokens/restrictions")?)
        .json(&serde_json::to_value(TokenRestrictionCreateRequest {
            restriction: obj,
        })?)
        .send()
        .await?
        .json::<TokenRestrictionResponse>()
        .await?
        .restriction)
}

pub async fn delete_token_restriction<U: AsRef<str>>(tc: &TestClient, id: U) -> Result<()> {
    let _ = tc
        .client
        .delete(
            tc.base_url
                .join("v4/tokens/restrictions/")?
                .join(id.as_ref())?,
        )
        .send()
        .await?;
    Ok(())
}

pub async fn auth<I: AsRef<str>>(
    tc: &TestClient,
    instance_id: I,
    obj: K8sAuthRequest,
) -> Result<(Token, SecretString)> {
    let rsp = tc
        .client
        .post(
            tc.base_url
                .join(format!("v4/k8s_auth/instances/{}/auth", instance_id.as_ref()).as_str())?,
        )
        .json(&serde_json::to_value(obj)?)
        .send()
        .await?;

    if rsp.status() != StatusCode::OK {
        return Err(eyre!("Authentication failed with {}", rsp.status()));
    }

    let token = SecretString::from(
        rsp.headers()
            .get("X-Subject-Token")
            .ok_or_else(|| eyre!("Token is missing in the {:?}", rsp))?
            .to_str()?,
    );
    Ok((rsp.json::<TokenResponse>().await?.token, token))
}

#[tokio::test]
async fn test_k8s_auth() -> Result<()> {
    let mut test_client = TestClient::default()?;
    test_client.auth_admin().await?;

    let k8s_ca = fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt").await?;

    let user_create = UserCreate {
        name: Uuid::new_v4().to_string(),
        domain_id: "default".into(),
        ..Default::default()
    };
    let instance_create = K8sAuthInstanceCreate {
        ca_cert: Some(k8s_ca.into()),
        disable_local_ca_jwt: Some(true),
        domain_id: "default".into(),
        enabled: true,
        host: "https://kubernetes.default.svc".into(),
        name: Some(uuid::Uuid::new_v4().simple().to_string()),
    };
    let project_create = ProjectCreate {
        domain_id: "default".into(),
        name: uuid::Uuid::new_v4().simple().to_string(),
        enabled: true,
        ..Default::default()
    };
    let user = create_user(&test_client, user_create).await?;
    let instance = create_auth_instance(&test_client, instance_create).await?;
    let project = create_project(&test_client, project_create).await?;
    let tr_create = TokenRestrictionCreate {
        allow_renew: false,
        allow_rescope: false,
        domain_id: "default".into(),
        project_id: Some(project.id.clone()),
        user_id: Some(user.id.clone()),
        roles: vec![],
    };
    let tr = create_token_restriction(&test_client, tr_create).await?;
    let role_create = K8sAuthRoleCreate {
        bound_audience: None,
        bound_service_account_names: vec![],
        bound_service_account_namespaces: vec![],
        enabled: true,
        name: uuid::Uuid::new_v4().simple().to_string(),
        token_restriction_id: tr.id.clone(),
    };
    let k8s_role = create_auth_role(&test_client, &instance.id, role_create).await?;

    // Now read the (hopefully not expired) K8 token
    let k8s_token =
        fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token").await?;

    let auth_data = K8sAuthRequest {
        jwt: SecretString::from(k8s_token),
        role_name: k8s_role.name.clone(),
    };
    let (token_data, token_secret) = auth(&test_client, &instance.id, auth_data).await?;

    assert_eq!(token_data.user.id, user.id);
    assert_eq!(
        token_data.project.expect("must be project scope").id,
        project.id
    );

    delete_auth_instance(&test_client, &instance.id).await?;
    delete_user(&test_client, &user.id).await?;
    delete_project(&test_client, &project.id).await?;
    Ok(())
}
