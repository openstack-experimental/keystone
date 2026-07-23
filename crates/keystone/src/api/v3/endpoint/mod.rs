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
//! # Endpoint API

use std::collections::HashMap;

use serde_json::Value;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::RegionCreate;

mod create;
mod delete;
mod list;
mod show;
pub mod types;
mod update;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list, create::create))
        .routes(routes!(show::show, delete::delete))
        .routes(routes!(update::update))
}

/// Resolves the deprecated `region` endpoint attribute (captured in
/// `extra` since it has no dedicated field) to `region_id`, auto-vivifying
/// a `Region` with that id if none exists yet -- matching python
/// keystone's back-compat behavior for the legacy `region` field.
///
/// Returns the resolved `region_id`, or the pre-existing one unchanged if
/// `region_id` was already set or no legacy `region` was given.
pub(super) async fn resolve_legacy_region<'a>(
    state: &ServiceState,
    exec: &ExecutionContext<'a>,
    region_id: Option<String>,
    extra: &mut HashMap<String, Value>,
) -> Result<Option<String>, KeystoneApiError> {
    if region_id.is_some() {
        return Ok(region_id);
    }
    let Some(region_id) = extra
        .remove("region")
        .and_then(|v| v.as_str().map(str::to_string))
    else {
        return Ok(None);
    };
    if state
        .provider
        .get_catalog_provider()
        .get_region(exec, &region_id)
        .await?
        .is_none()
    {
        state
            .provider
            .get_catalog_provider()
            .create_region(
                exec,
                RegionCreate {
                    id: Some(region_id.clone()),
                    description: None,
                    extra: Default::default(),
                    parent_region_id: None,
                },
            )
            .await?;
    }
    Ok(Some(region_id))
}
