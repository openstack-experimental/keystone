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
//! Helpers for the unified limits API (`/v3/registered_limits`, `/v3/limits`).
use std::borrow::Cow;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone_api_types::v3::limit::*;
use openstack_keystone_api_types::v3::registered_limit::*;
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

/// Generic request against the limits API.
#[derive(Clone, Debug)]
struct LimitsRequest {
    method: http::Method,
    endpoint: String,
    body: Option<(&'static str, serde_json::Value)>,
    response_key: Option<&'static str>,
    query: Vec<(&'static str, String)>,
}

impl RestEndpoint for LimitsRequest {
    fn method(&self) -> http::Method {
        self.method.clone()
    }

    fn endpoint(&self) -> Cow<'static, str> {
        self.endpoint.clone().into()
    }

    fn parameters(&self) -> QueryParams<'_> {
        let mut params = QueryParams::default();
        for (key, value) in &self.query {
            params.push(*key, value);
        }
        params
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        match &self.body {
            Some((key, value)) => {
                let mut params = JsonBodyParams::default();
                params.push(*key, value.clone());
                params.into_body()
            }
            None => Ok(None),
        }
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        self.response_key.map(Into::into)
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

fn request(
    method: http::Method,
    endpoint: impl Into<String>,
    response_key: Option<&'static str>,
) -> LimitsRequest {
    LimitsRequest {
        method,
        endpoint: endpoint.into(),
        body: None,
        response_key,
        query: Vec::new(),
    }
}

/// Create registered limits (batch).
pub async fn create_registered_limits(
    tc: &Arc<AsyncOpenStack>,
    limits: Vec<RegisteredLimitCreate>,
) -> Result<Vec<AsyncResourceGuard<RegisteredLimit>>> {
    let mut req = request(
        http::Method::POST,
        "registered_limits",
        Some("registered_limits"),
    );
    req.body = Some(("registered_limits", serde_json::to_value(&limits)?));
    let created: Vec<RegisteredLimit> = req.query_async(tc.as_ref()).await?;
    Ok(created
        .into_iter()
        .map(|obj| AsyncResourceGuard::new(obj, tc.clone()))
        .collect())
}

/// Get a registered limit by ID.
pub async fn show_registered_limit<I: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    id: I,
) -> Result<RegisteredLimit> {
    Ok(request(
        http::Method::GET,
        format!("registered_limits/{}", id.as_ref()),
        Some("registered_limit"),
    )
    .query_async(tc.as_ref())
    .await?)
}

/// List registered limits with the optional `(name, value)` filters.
pub async fn list_registered_limits(
    tc: &Arc<AsyncOpenStack>,
    filters: &[(&'static str, &str)],
) -> Result<Vec<RegisteredLimit>> {
    let mut req = request(
        http::Method::GET,
        "registered_limits",
        Some("registered_limits"),
    );
    req.query = filters.iter().map(|(k, v)| (*k, v.to_string())).collect();
    Ok(req.query_async(tc.as_ref()).await?)
}

/// Update a registered limit.
pub async fn update_registered_limit<I: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    id: I,
    data: RegisteredLimitUpdate,
) -> Result<RegisteredLimit> {
    let mut req = request(
        http::Method::PATCH,
        format!("registered_limits/{}", id.as_ref()),
        Some("registered_limit"),
    );
    req.body = Some(("registered_limit", serde_json::to_value(&data)?));
    Ok(req.query_async(tc.as_ref()).await?)
}

/// Delete a registered limit.
pub async fn delete_registered_limit<I: AsRef<str>>(tc: &Arc<AsyncOpenStack>, id: I) -> Result<()> {
    Ok(openstack_sdk::api::ignore(request(
        http::Method::DELETE,
        format!("registered_limits/{}", id.as_ref()),
        None,
    ))
    .query_async(tc.as_ref())
    .await?)
}

/// Create limits (batch).
pub async fn create_limits(
    tc: &Arc<AsyncOpenStack>,
    limits: Vec<LimitCreate>,
) -> Result<Vec<AsyncResourceGuard<Limit>>> {
    let mut req = request(http::Method::POST, "limits", Some("limits"));
    req.body = Some(("limits", serde_json::to_value(&limits)?));
    let created: Vec<Limit> = req.query_async(tc.as_ref()).await?;
    Ok(created
        .into_iter()
        .map(|obj| AsyncResourceGuard::new(obj, tc.clone()))
        .collect())
}

/// Get a limit by ID.
pub async fn show_limit<I: AsRef<str>>(tc: &Arc<AsyncOpenStack>, id: I) -> Result<Limit> {
    Ok(request(
        http::Method::GET,
        format!("limits/{}", id.as_ref()),
        Some("limit"),
    )
    .query_async(tc.as_ref())
    .await?)
}

/// List limits with the optional `(name, value)` filters.
pub async fn list_limits(
    tc: &Arc<AsyncOpenStack>,
    filters: &[(&'static str, &str)],
) -> Result<Vec<Limit>> {
    let mut req = request(http::Method::GET, "limits", Some("limits"));
    req.query = filters.iter().map(|(k, v)| (*k, v.to_string())).collect();
    Ok(req.query_async(tc.as_ref()).await?)
}

/// Update a limit.
pub async fn update_limit<I: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    id: I,
    data: LimitUpdate,
) -> Result<Limit> {
    let mut req = request(
        http::Method::PATCH,
        format!("limits/{}", id.as_ref()),
        Some("limit"),
    );
    req.body = Some(("limit", serde_json::to_value(&data)?));
    Ok(req.query_async(tc.as_ref()).await?)
}

/// Delete a limit.
pub async fn delete_limit<I: AsRef<str>>(tc: &Arc<AsyncOpenStack>, id: I) -> Result<()> {
    Ok(openstack_sdk::api::ignore(request(
        http::Method::DELETE,
        format!("limits/{}", id.as_ref()),
        None,
    ))
    .query_async(tc.as_ref())
    .await?)
}

/// Get the enforcement model.
pub async fn get_limit_model(tc: &Arc<AsyncOpenStack>) -> Result<LimitModel> {
    Ok(request(http::Method::GET, "limits/model", Some("model"))
        .query_async(tc.as_ref())
        .await?)
}

#[async_trait::async_trait]
impl DeletableResource for RegisteredLimit {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        delete_registered_limit(state, &self.id).await
    }
}

#[async_trait::async_trait]
impl DeletableResource for Limit {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        delete_limit(state, &self.id).await
    }
}
