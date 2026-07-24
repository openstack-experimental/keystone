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
//! OS-EC2 credential helpers (`/v3/users/{user_id}/credentials/OS-EC2`).
//!
//! These are user-subresource paths (two path parameters), so the request
//! impls are hand-written rather than `crud_endpoint!`-generated.

use std::borrow::Cow;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone_api_types::v3::os_ec2_credential::*;
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

#[derive(Clone, Debug)]
struct Ec2CredentialCreateApiRequest {
    user_id: String,
    body: Ec2CredentialCreateRequest,
}

impl RestEndpoint for Ec2CredentialCreateApiRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("users/{}/credentials/OS-EC2", self.user_id).into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("tenant_id", serde_json::to_value(&self.body.project_id)?);
        if let Some(access) = &self.body.access {
            params.push("access", serde_json::to_value(access)?);
        }
        if let Some(secret) = &self.body.secret {
            params.push("secret", serde_json::to_value(secret)?);
        }
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("credential".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Create an EC2 credential for `user_id` bound to `project_id`.
pub async fn create_ec2_credential(
    tc: &Arc<AsyncOpenStack>,
    user_id: &str,
    project_id: &str,
) -> Result<Ec2Credential> {
    Ok(Ec2CredentialCreateApiRequest {
        user_id: user_id.to_string(),
        body: Ec2CredentialCreateRequest {
            project_id: project_id.to_string(),
            access: None,
            secret: None,
        },
    }
    .query_async(tc.as_ref())
    .await?)
}

#[derive(Clone, Debug)]
struct Ec2CredentialShowApiRequest {
    user_id: String,
    credential_id: String,
}

impl RestEndpoint for Ec2CredentialShowApiRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!(
            "users/{}/credentials/OS-EC2/{}",
            self.user_id, self.credential_id
        )
        .into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("credential".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Show a single EC2 credential (`credential_id` is the access key).
pub async fn get_ec2_credential(
    tc: &Arc<AsyncOpenStack>,
    user_id: &str,
    credential_id: &str,
) -> Result<Ec2Credential> {
    Ok(Ec2CredentialShowApiRequest {
        user_id: user_id.to_string(),
        credential_id: credential_id.to_string(),
    }
    .query_async(tc.as_ref())
    .await?)
}

#[derive(Clone, Debug)]
struct Ec2CredentialListApiRequest {
    user_id: String,
}

impl RestEndpoint for Ec2CredentialListApiRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("users/{}/credentials/OS-EC2", self.user_id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("credentials".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// List the EC2 credentials of `user_id`.
pub async fn list_ec2_credentials(
    tc: &Arc<AsyncOpenStack>,
    user_id: &str,
) -> Result<Vec<Ec2Credential>> {
    Ok(Ec2CredentialListApiRequest {
        user_id: user_id.to_string(),
    }
    .query_async(tc.as_ref())
    .await?)
}

#[derive(Clone, Debug)]
struct Ec2CredentialDeleteApiRequest {
    user_id: String,
    credential_id: String,
}

impl RestEndpoint for Ec2CredentialDeleteApiRequest {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!(
            "users/{}/credentials/OS-EC2/{}",
            self.user_id, self.credential_id
        )
        .into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Delete an EC2 credential (`credential_id` is the access key).
pub async fn delete_ec2_credential(
    tc: &Arc<AsyncOpenStack>,
    user_id: &str,
    credential_id: &str,
) -> Result<()> {
    Ok(openstack_sdk::api::ignore(Ec2CredentialDeleteApiRequest {
        user_id: user_id.to_string(),
        credential_id: credential_id.to_string(),
    })
    .query_async(tc.as_ref())
    .await?)
}
