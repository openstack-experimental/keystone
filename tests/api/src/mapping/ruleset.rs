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
//! Mapping ruleset REST endpoint helpers and test infrastructure.

use std::borrow::Cow;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone_api_types::v4::mapping::ruleset::{
    MappingRuleSet, MappingRuleSetCreate, MappingRuleSetUpdate, RuleMutationsRequest,
};
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

mod create;
mod delete;
mod is_system;
mod list;
mod mutate;
mod show;
mod update;

// ---------------------------------------------------------------------------
// REST Endpoint Implementations
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct MappingRuleSetCreateRequest {
    ruleset: MappingRuleSetCreate,
}

impl RestEndpoint for MappingRuleSetCreateRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "mappings/rulesets".into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("mapping", serde_json::to_value(&self.ruleset)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("mapping".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

#[derive(Clone, Debug)]
struct MappingRuleSetShowRequest<'a> {
    mapping_id: Cow<'a, str>,
}

impl RestEndpoint for MappingRuleSetShowRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("mappings/rulesets/{}", self.mapping_id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("mapping".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

#[derive(Default, Clone, Debug)]
pub struct MappingRuleSetListParameters {
    pub domain_id: Option<String>,
    pub enabled: Option<bool>,
    pub limit: Option<u64>,
    pub marker: Option<String>,
}

impl RestEndpoint for MappingRuleSetListParameters {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "mappings/rulesets".into()
    }

    fn parameters(&self) -> QueryParams<'_> {
        let mut params = QueryParams::default();
        params.push_opt("domain_id", self.domain_id.as_ref());
        params.push_opt("enabled", self.enabled);
        params.push_opt("limit", self.limit);
        params.push_opt("marker", self.marker.as_ref());
        params
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("mappings".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

#[derive(Clone, Debug)]
struct MappingRuleSetUpdateRequest<'a> {
    mapping_id: Cow<'a, str>,
    ruleset: MappingRuleSetUpdate,
}

impl RestEndpoint for MappingRuleSetUpdateRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::PUT
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("mappings/rulesets/{}", self.mapping_id).into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("mapping", serde_json::to_value(&self.ruleset)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("mapping".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

#[derive(Clone, Debug)]
struct MappingRuleSetMutateRequest<'a> {
    mapping_id: Cow<'a, str>,
    mutations: RuleMutationsRequest,
}

impl RestEndpoint for MappingRuleSetMutateRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("mappings/rulesets/{id}/rules/mutate", id = self.mapping_id).into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        Ok(Some((
            "application/json",
            serde_json::to_vec(&self.mutations)?,
        )))
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("mapping".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

#[derive(Clone, Debug)]
struct MappingRuleSetDeleteRequest<'a> {
    mapping_id: Cow<'a, str>,
}

impl RestEndpoint for MappingRuleSetDeleteRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("mappings/rulesets/{}", self.mapping_id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

pub async fn create_ruleset(
    tc: &Arc<AsyncOpenStack>,
    ruleset: MappingRuleSetCreate,
) -> Result<AsyncResourceGuard<MappingRuleSet>> {
    let obj: MappingRuleSet = MappingRuleSetCreateRequest { ruleset }
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

pub async fn show_ruleset<I: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    mapping_id: I,
) -> Result<MappingRuleSet> {
    Ok(MappingRuleSetShowRequest {
        mapping_id: mapping_id.as_ref().into(),
    }
    .query_async(tc.as_ref())
    .await?)
}

pub async fn list_ruleset(tc: &Arc<AsyncOpenStack>) -> Result<Vec<MappingRuleSet>> {
    Ok(MappingRuleSetListParameters::default()
        .query_async(tc.as_ref())
        .await?)
}

pub async fn update_ruleset<I: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    mapping_id: I,
    update: MappingRuleSetUpdate,
) -> Result<MappingRuleSet> {
    Ok(MappingRuleSetUpdateRequest {
        mapping_id: mapping_id.as_ref().into(),
        ruleset: update,
    }
    .query_async(tc.as_ref())
    .await?)
}

pub async fn mutate_ruleset<I: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    mapping_id: I,
    mutations: RuleMutationsRequest,
) -> Result<MappingRuleSet> {
    Ok(MappingRuleSetMutateRequest {
        mapping_id: mapping_id.as_ref().into(),
        mutations,
    }
    .query_async(tc.as_ref())
    .await?)
}

#[async_trait::async_trait]
impl DeletableResource for MappingRuleSet {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(MappingRuleSetDeleteRequest {
            mapping_id: self.mapping_id.clone().into(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}
