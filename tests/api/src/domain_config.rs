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
//! SDK bindings for the `/v3/domains/{domain_id}/config` domain-configuration
//! API.
//!
//! Every payload nests under a single `config` key
//! (`{"config": {"<group>": {"<option>": <value>}}}`); group- and
//! option-scoped requests use the same envelope with only the addressed group
//! present. Used by the ADR 0034 §6 authorization tests, which check that the
//! `assignment` group is writable only by a cloud admin.

use std::borrow::Cow;
use std::sync::Arc;

use eyre::Result;
use serde_json::{Value, json};

use openstack_keystone_api_types::v3::domain_config::DomainConfigResponse;
use openstack_sdk::AsyncOpenStack;
use openstack_sdk::api::QueryAsync;
use openstack_sdk::api::rest_endpoint_prelude::*;

/// One `config` write or read, parameterised by method and path so the
/// whole-config, group and option shapes share a single impl.
struct DomainConfigRequest {
    method: http::Method,
    endpoint: String,
    body: Option<Value>,
}

impl RestEndpoint for DomainConfigRequest {
    fn method(&self) -> http::Method {
        self.method.clone()
    }

    fn endpoint(&self) -> Cow<'static, str> {
        self.endpoint.clone().into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        match &self.body {
            Some(config) => {
                let mut params = JsonBodyParams::default();
                params.push("config", config.clone());
                params.into_body()
            }
            None => Ok(None),
        }
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

async fn send(client: &Arc<AsyncOpenStack>, request: DomainConfigRequest) -> Result<Value> {
    let response: DomainConfigResponse = request.query_async(client.as_ref()).await?;
    Ok(response.config)
}

/// `PUT /v3/domains/{domain_id}/config` — create (replace) the whole
/// configuration. `body` is the group map, e.g.
/// `json!({"assignment": {"driver": "sql"}})`.
pub async fn replace_domain_config(
    client: &Arc<AsyncOpenStack>,
    domain_id: &str,
    body: Value,
) -> Result<Value> {
    send(
        client,
        DomainConfigRequest {
            method: http::Method::PUT,
            endpoint: format!("domains/{domain_id}/config"),
            body: Some(body),
        },
    )
    .await
}

/// `PATCH /v3/domains/{domain_id}/config/{group}` — merge changes into one
/// group.
pub async fn patch_domain_config_group(
    client: &Arc<AsyncOpenStack>,
    domain_id: &str,
    group: &str,
    body: Value,
) -> Result<Value> {
    send(
        client,
        DomainConfigRequest {
            method: http::Method::PATCH,
            endpoint: format!("domains/{domain_id}/config/{group}"),
            body: Some(body),
        },
    )
    .await
}

/// `PATCH /v3/domains/{domain_id}/config/{group}/{option}` — merge one option.
pub async fn patch_domain_config_option(
    client: &Arc<AsyncOpenStack>,
    domain_id: &str,
    group: &str,
    option: &str,
    body: Value,
) -> Result<Value> {
    send(
        client,
        DomainConfigRequest {
            method: http::Method::PATCH,
            endpoint: format!("domains/{domain_id}/config/{group}/{option}"),
            body: Some(body),
        },
    )
    .await
}

/// `GET /v3/domains/{domain_id}/config/{group}` — read one stored group.
pub async fn get_domain_config_group(
    client: &Arc<AsyncOpenStack>,
    domain_id: &str,
    group: &str,
) -> Result<Value> {
    send(
        client,
        DomainConfigRequest {
            method: http::Method::GET,
            endpoint: format!("domains/{domain_id}/config/{group}"),
            body: None,
        },
    )
    .await
}

/// `{"<group>": {"driver": "<driver>"}}` — the single-option write body the
/// binding tests pass to every write shape.
pub fn driver_body(group: &str, driver: &str) -> Value {
    json!({ group: { "driver": driver } })
}
