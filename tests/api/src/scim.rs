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
//! Raw-`reqwest` client for `/SCIM/v2/{domain_id}/...` (ADR 0021 §2, ADR
//! 0024). This is **not** an OpenStack-catalog service, so it can't go
//! through `AsyncOpenStack`'s `RestEndpoint`/`QueryAsync` machinery like
//! `test_api::scim_realm` does -- it's a bespoke bearer-token protocol,
//! following `TestClient`'s raw-HTTP pattern (`test_api::common`) instead.
//!
//! Wire types here are a deliberately independent re-declaration of
//! `crates/keystone/src/scim/types.rs`'s shapes, not a shared import: this
//! crate runs against a live remote server binary and has no dependency on
//! the `openstack-keystone` service crate, so cross-checking the two is
//! exactly what makes this suite meaningful.

use std::env;

use eyre::{Result, WrapErr, eyre};
use reqwest::{Client, StatusCode, header::HeaderMap};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimEmail {
    pub value: String,
    #[serde(default)]
    pub primary: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMeta {
    pub resource_type: String,
    pub location: String,
    pub created: String,
    pub last_modified: String,
}

/// `GET`/`POST`/`PUT` SCIM `User` representation.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(default)]
    pub external_id: Option<String>,
    pub user_name: String,
    #[serde(default)]
    pub name: Option<ScimName>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub emails: Vec<ScimEmail>,
    pub active: bool,
    pub meta: ScimMeta,
}

/// `POST`/`PUT` SCIM `User` request body.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUserWrite {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<ScimEmail>,
    pub active: bool,
}

impl ScimUserWrite {
    pub fn new<U: Into<String>>(user_name: U) -> Self {
        let user_name = user_name.into();
        Self {
            schemas: vec![USER_SCHEMA.to_string()],
            external_id: Some(user_name.clone()),
            user_name,
            active: true,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimListResponse<T> {
    pub schemas: Vec<String>,
    pub total_results: usize,
    pub start_index: usize,
    pub items_per_page: usize,
    pub resources: Vec<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroupMember {
    pub value: String,
}

/// `GET`/`POST`/`PUT` SCIM `Group` representation.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroup {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(default)]
    pub external_id: Option<String>,
    pub display_name: String,
    #[serde(default)]
    pub members: Vec<ScimGroupMember>,
    pub meta: ScimMeta,
}

/// `POST`/`PUT` SCIM `Group` request body.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroupWrite {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<ScimGroupMember>,
}

impl ScimGroupWrite {
    pub fn new<D: Into<String>>(display_name: D) -> Self {
        Self {
            schemas: vec![GROUP_SCHEMA.to_string()],
            display_name: display_name.into(),
            ..Default::default()
        }
    }
}

pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

#[derive(Debug, Clone, Serialize)]
pub struct ScimPatchOperation {
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub value: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScimPatchRequest {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<ScimPatchOperation>,
}

impl ScimPatchRequest {
    pub fn replace<P: Into<String>>(path: P, value: Value) -> Self {
        Self {
            schemas: vec![PATCH_SCHEMA.to_string()],
            operations: vec![ScimPatchOperation {
                op: "replace".to_string(),
                path: Some(path.into()),
                value,
            }],
        }
    }
}

/// RFC 7644 §3.12 SCIM error response body.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimErrorBody {
    #[serde(default)]
    pub schemas: Vec<String>,
    pub status: String,
    #[serde(default)]
    pub scim_type: Option<String>,
    #[serde(default)]
    pub detail: String,
}

/// A response with the pieces the test suites actually assert on: status,
/// `ETag`, and a body that's lazily parsed by the caller (success and error
/// bodies have different shapes).
pub struct ScimResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: bytes::Bytes,
}

impl ScimResponse {
    pub fn etag(&self) -> Option<&str> {
        self.headers.get("etag").and_then(|v| v.to_str().ok())
    }

    pub fn location(&self) -> Option<&str> {
        self.headers.get("location").and_then(|v| v.to_str().ok())
    }

    pub fn json<T: for<'de> Deserialize<'de>>(&self) -> Result<T> {
        Ok(serde_json::from_slice(&self.body)?)
    }

    pub fn error(&self) -> Result<ScimErrorBody> {
        self.json()
    }
}

/// Bearer-token client for `/SCIM/v2/{domain_id}/...`.
pub struct ScimTestClient {
    client: Client,
    base_url: Url,
    domain_id: String,
    token: SecretString,
}

impl ScimTestClient {
    /// `token` is the `kscim_...` bearer value returned once by `POST
    /// /v4/api-keys`.
    pub fn new(domain_id: impl Into<String>, token: SecretString) -> Result<Self> {
        let base_url: Url = env::var("KEYSTONE_URL")
            .wrap_err("KEYSTONE_URL must be set")?
            .parse()?;
        Ok(Self {
            client: Client::new(),
            base_url,
            domain_id: domain_id.into(),
            token,
        })
    }

    fn url(&self, path: &str) -> Result<Url> {
        Ok(self
            .base_url
            .join(&format!("SCIM/v2/{}/{}", self.domain_id, path))?)
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        if_match: Option<&str>,
    ) -> Result<ScimResponse> {
        let mut req = self
            .client
            .request(method, self.url(path)?)
            .bearer_auth(self.token.expose_secret());
        if let Some(body) = body {
            req = req.json(&body);
        }
        if let Some(if_match) = if_match {
            req = req.header("if-match", if_match);
        }
        let rsp = req.send().await?;
        let status = rsp.status();
        let headers = rsp.headers().clone();
        let body = rsp.bytes().await?;
        Ok(ScimResponse {
            status,
            headers,
            body,
        })
    }

    pub async fn create_user(&self, user: &ScimUserWrite) -> Result<ScimResponse> {
        self.send(
            reqwest::Method::POST,
            "Users",
            Some(serde_json::to_value(user)?),
            None,
        )
        .await
    }

    pub async fn list_users(&self, query: &str) -> Result<ScimResponse> {
        let path = if query.is_empty() {
            "Users".to_string()
        } else {
            format!("Users?{query}")
        };
        self.send(reqwest::Method::GET, &path, None, None).await
    }

    pub async fn show_user(&self, id: &str) -> Result<ScimResponse> {
        self.send(reqwest::Method::GET, &format!("Users/{id}"), None, None)
            .await
    }

    pub async fn update_user(
        &self,
        id: &str,
        user: &ScimUserWrite,
        if_match: Option<&str>,
    ) -> Result<ScimResponse> {
        self.send(
            reqwest::Method::PUT,
            &format!("Users/{id}"),
            Some(serde_json::to_value(user)?),
            if_match,
        )
        .await
    }

    pub async fn patch_user(&self, id: &str, patch: &ScimPatchRequest) -> Result<ScimResponse> {
        self.send(
            reqwest::Method::PATCH,
            &format!("Users/{id}"),
            Some(serde_json::to_value(patch)?),
            None,
        )
        .await
    }

    pub async fn delete_user(&self, id: &str) -> Result<ScimResponse> {
        self.send(reqwest::Method::DELETE, &format!("Users/{id}"), None, None)
            .await
    }

    pub async fn create_group(&self, group: &ScimGroupWrite) -> Result<ScimResponse> {
        self.send(
            reqwest::Method::POST,
            "Groups",
            Some(serde_json::to_value(group)?),
            None,
        )
        .await
    }

    pub async fn list_groups(&self, query: &str) -> Result<ScimResponse> {
        let path = if query.is_empty() {
            "Groups".to_string()
        } else {
            format!("Groups?{query}")
        };
        self.send(reqwest::Method::GET, &path, None, None).await
    }

    pub async fn show_group(&self, id: &str) -> Result<ScimResponse> {
        self.send(reqwest::Method::GET, &format!("Groups/{id}"), None, None)
            .await
    }

    pub async fn update_group(
        &self,
        id: &str,
        group: &ScimGroupWrite,
        if_match: Option<&str>,
    ) -> Result<ScimResponse> {
        self.send(
            reqwest::Method::PUT,
            &format!("Groups/{id}"),
            Some(serde_json::to_value(group)?),
            if_match,
        )
        .await
    }

    pub async fn patch_group(&self, id: &str, patch: &ScimPatchRequest) -> Result<ScimResponse> {
        self.send(
            reqwest::Method::PATCH,
            &format!("Groups/{id}"),
            Some(serde_json::to_value(patch)?),
            None,
        )
        .await
    }

    pub async fn delete_group(&self, id: &str) -> Result<ScimResponse> {
        self.send(reqwest::Method::DELETE, &format!("Groups/{id}"), None, None)
            .await
    }

    pub async fn service_provider_config(&self) -> Result<ScimResponse> {
        self.send(reqwest::Method::GET, "ServiceProviderConfig", None, None)
            .await
    }

    pub async fn resource_types(&self) -> Result<ScimResponse> {
        self.send(reqwest::Method::GET, "ResourceTypes", None, None)
            .await
    }

    pub async fn schemas(&self) -> Result<ScimResponse> {
        self.send(reqwest::Method::GET, "Schemas", None, None).await
    }

    /// Sends an arbitrary method against a path with no body -- used to
    /// probe routing behavior (e.g. unmapped-method 405s) that the
    /// resource-specific helpers above can't express.
    pub async fn raw(&self, method: reqwest::Method, path: &str) -> Result<ScimResponse> {
        self.send(method, path, None, None).await
    }

    /// Sends a raw string body with an explicit (or absent) `Content-Type`
    /// header -- used to probe content-type negotiation and malformed-JSON
    /// handling, neither of which `send`'s `.json(&body)` can express (it
    /// always sets `application/json` and always serializes valid JSON).
    pub async fn raw_with_body(
        &self,
        method: reqwest::Method,
        path: &str,
        content_type: Option<&str>,
        body: &str,
    ) -> Result<ScimResponse> {
        let mut req = self
            .client
            .request(method, self.url(path)?)
            .bearer_auth(self.token.expose_secret())
            .body(body.to_string());
        if let Some(content_type) = content_type {
            req = req.header(reqwest::header::CONTENT_TYPE, content_type);
        }
        let rsp = req.send().await?;
        let status = rsp.status();
        let headers = rsp.headers().clone();
        let body = rsp.bytes().await?;
        Ok(ScimResponse {
            status,
            headers,
            body,
        })
    }
}

/// Expect a `2xx` response and parse its body as `T`, otherwise surface the
/// SCIM error envelope (or a raw-status fallback if the body isn't one).
pub async fn expect_ok<T: for<'de> Deserialize<'de>>(rsp: ScimResponse) -> Result<T> {
    if !rsp.status.is_success() {
        let detail = rsp
            .error()
            .map(|e| e.detail)
            .unwrap_or_else(|_| String::from_utf8_lossy(&rsp.body).to_string());
        return Err(eyre!("SCIM request failed with {}: {detail}", rsp.status));
    }
    rsp.json()
}
