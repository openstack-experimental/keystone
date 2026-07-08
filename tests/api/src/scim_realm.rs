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
//! SCIM realm (`/v4/scim_realms`, ADR 0024 §2) REST endpoint helpers.
//!
//! There is no delete endpoint -- a realm is only ever enabled/disabled via
//! `update` (ADR 0024 §2.B, the Realm Activation Gate), never removed. So,
//! unlike every other resource in this crate, [`ScimRealm`] does not
//! implement [`DeletableResource`]/[`AsyncResourceGuard`]; tests are
//! expected to use a unique `provider_id` per run and leave the (harmless,
//! disabled) realm row behind, exactly as `tests/integration/src/scim_realm`
//! does for the real-backend suite.

use std::borrow::Cow;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone_api_types::v4::scim_realm::{ScimRealm, ScimRealmCreate, ScimRealmUpdate};
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

/// Local list-query struct: the orphan rule blocks implementing the foreign
/// `RestEndpoint` trait directly on `api_types::ScimRealmListParameters`
/// (mirrors `test_api::mapping::ruleset::MappingRuleSetListParameters`).
#[derive(Default, Clone, Debug)]
pub struct ScimRealmListParameters {
    pub domain_id: String,
    pub enabled: Option<bool>,
}

#[derive(Clone, Debug)]
struct ScimRealmCreateRequest {
    scim_realm: ScimRealmCreate,
}

impl RestEndpoint for ScimRealmCreateRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "scim_realms".into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("scim_realm", serde_json::to_value(&self.scim_realm)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("scim_realm".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

#[derive(Clone, Debug)]
struct ScimRealmShowRequest<'a> {
    domain_id: Cow<'a, str>,
    provider_id: Cow<'a, str>,
}

impl RestEndpoint for ScimRealmShowRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("scim_realms/{}/{}", self.domain_id, self.provider_id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("scim_realm".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

impl RestEndpoint for ScimRealmListParameters {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "scim_realms".into()
    }

    fn parameters(&self) -> QueryParams<'_> {
        let mut params = QueryParams::default();
        params.push("domain_id", self.domain_id.as_str());
        params.push_opt("enabled", self.enabled);
        params
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("scim_realms".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

#[derive(Clone, Debug)]
struct ScimRealmUpdateRequest<'a> {
    domain_id: Cow<'a, str>,
    provider_id: Cow<'a, str>,
    scim_realm: ScimRealmUpdate,
}

impl RestEndpoint for ScimRealmUpdateRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::PUT
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("scim_realms/{}/{}", self.domain_id, self.provider_id).into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("scim_realm", serde_json::to_value(&self.scim_realm)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("scim_realm".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

#[derive(Clone, Debug)]
struct ScimRealmPurgeRequest<'a> {
    domain_id: Cow<'a, str>,
    provider_id: Cow<'a, str>,
    resource_type: Cow<'a, str>,
    keystone_id: Cow<'a, str>,
}

impl RestEndpoint for ScimRealmPurgeRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!(
            "scim_realms/{}/{}/purge/{}/{}",
            self.domain_id, self.provider_id, self.resource_type, self.keystone_id
        )
        .into()
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

pub async fn create_realm(
    tc: &Arc<AsyncOpenStack>,
    scim_realm: ScimRealmCreate,
) -> Result<ScimRealm> {
    Ok(ScimRealmCreateRequest { scim_realm }
        .query_async(tc.as_ref())
        .await?)
}

pub async fn show_realm<D: AsRef<str>, P: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    domain_id: D,
    provider_id: P,
) -> Result<ScimRealm> {
    Ok(ScimRealmShowRequest {
        domain_id: domain_id.as_ref().into(),
        provider_id: provider_id.as_ref().into(),
    }
    .query_async(tc.as_ref())
    .await?)
}

pub async fn list_realms(
    tc: &Arc<AsyncOpenStack>,
    params: ScimRealmListParameters,
) -> Result<Vec<ScimRealm>> {
    Ok(params.query_async(tc.as_ref()).await?)
}

pub async fn update_realm<D: AsRef<str>, P: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    domain_id: D,
    provider_id: P,
    scim_realm: ScimRealmUpdate,
) -> Result<ScimRealm> {
    Ok(ScimRealmUpdateRequest {
        domain_id: domain_id.as_ref().into(),
        provider_id: provider_id.as_ref().into(),
        scim_realm,
    }
    .query_async(tc.as_ref())
    .await?)
}

/// Bypasses the janitor's retention window for a single already-
/// deprovisioned resource (ADR 0024 §6.C).
pub async fn purge_resource<D: AsRef<str>, P: AsRef<str>, K: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    domain_id: D,
    provider_id: P,
    resource_type: &str,
    keystone_id: K,
) -> Result<()> {
    Ok(openstack_sdk::api::ignore(ScimRealmPurgeRequest {
        domain_id: domain_id.as_ref().into(),
        provider_id: provider_id.as_ref().into(),
        resource_type: resource_type.into(),
        keystone_id: keystone_id.as_ref().into(),
    })
    .query_async(tc.as_ref())
    .await?)
}

/// A realm create payload scoped to `domain_id`/`provider_id`/`idp_id`.
pub fn sample_realm_create(domain_id: &str, provider_id: &str, idp_id: &str) -> ScimRealmCreate {
    ScimRealmCreate {
        domain_id: domain_id.to_string(),
        provider_id: provider_id.to_string(),
        idp_id: idp_id.to_string(),
        display_name: "test_api SCIM realm".to_string(),
    }
}
