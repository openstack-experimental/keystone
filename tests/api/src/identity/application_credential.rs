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
use crate::guard::*;
use eyre::Result;
use openstack_keystone_api_types::v3::application_credential::application_credential::*;
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};
use std::borrow::Cow;
use std::sync::Arc;

struct AppCredCreateRequest {
    user_id: String,
    app_cred: ApplicationCredentialCreate,
}

impl RestEndpoint for AppCredCreateRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }
    fn endpoint(&self) -> Cow<'static, str> {
        format!("users/{}/application_credentials", self.user_id).into()
    }
    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push(
            "application_credential",
            serde_json::to_value(&self.app_cred)?,
        );
        params.into_body()
    }
    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }
    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("application_credential".into())
    }
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

struct AppCredDeleteRequest {
    user_id: String,
    id: String,
}

impl RestEndpoint for AppCredDeleteRequest {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }
    fn endpoint(&self) -> Cow<'static, str> {
        format!("users/{}/application_credentials/{}", self.user_id, self.id).into()
    }
    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

pub struct DeletableApplicationCredential {
    pub credential: ApplicationCredentialCreated,
    pub user_id: String,
}

#[async_trait::async_trait]
impl DeletableResource for DeletableApplicationCredential {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(AppCredDeleteRequest {
            user_id: self.user_id.clone(),
            id: self.credential.id.clone(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}

impl std::ops::Deref for DeletableApplicationCredential {
    type Target = ApplicationCredentialCreated;
    fn deref(&self) -> &Self::Target {
        &self.credential
    }
}

pub async fn create_application_credential(
    tc: &Arc<AsyncOpenStack>,
    user_id: &str,
    app_cred: ApplicationCredentialCreate,
) -> Result<AsyncResourceGuard<DeletableApplicationCredential>> {
    let obj: ApplicationCredentialCreated = AppCredCreateRequest {
        user_id: user_id.to_string(),
        app_cred,
    }
    .query_async(tc.as_ref())
    .await?;
    Ok(AsyncResourceGuard::new(
        DeletableApplicationCredential {
            credential: obj,
            user_id: user_id.to_string(),
        },
        tc.clone(),
    ))
}

struct AppCredGetRequest {
    user_id: String,
    id: String,
}

impl RestEndpoint for AppCredGetRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }
    fn endpoint(&self) -> Cow<'static, str> {
        format!("users/{}/application_credentials/{}", self.user_id, self.id).into()
    }
    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }
    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("application_credential".into())
    }
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

struct AppCredListRequest {
    user_id: String,
}

impl RestEndpoint for AppCredListRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }
    fn endpoint(&self) -> Cow<'static, str> {
        format!("users/{}/application_credentials", self.user_id).into()
    }
    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }
    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("application_credentials".into())
    }
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

pub async fn get_application_credential(
    tc: &Arc<AsyncOpenStack>,
    user_id: &str,
    id: &str,
) -> Result<ApplicationCredential> {
    use openstack_keystone_api_types::v3::application_credential::application_credential::ApplicationCredential;
    let obj: ApplicationCredential = AppCredGetRequest {
        user_id: user_id.to_string(),
        id: id.to_string(),
    }
    .query_async(tc.as_ref())
    .await?;
    Ok(obj)
}

pub async fn list_application_credentials(
    tc: &Arc<AsyncOpenStack>,
    user_id: &str,
) -> Result<Vec<ApplicationCredential>> {
    use openstack_keystone_api_types::v3::application_credential::application_credential::ApplicationCredential;
    let objs: Vec<ApplicationCredential> = AppCredListRequest {
        user_id: user_id.to_string(),
    }
    .query_async(tc.as_ref())
    .await?;
    Ok(objs)
}
