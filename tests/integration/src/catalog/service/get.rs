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
//! Test fetching a single service.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::catalog::CatalogApi;
use openstack_keystone_core_types::catalog::ServiceCreate;

use crate::catalog::create_service;
use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_get() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let mut extra = HashMap::new();
    extra.insert(
        "name".to_string(),
        serde_json::Value::String("glance".to_string()),
    );
    let service = create_service(
        &state,
        ServiceCreate {
            enabled: true,
            extra,
            id: Some("service-get".to_string()),
            r#type: Some("image".to_string()),
        },
    )
    .await?;

    let fetched = state
        .provider
        .get_catalog_provider()
        .get_service(&state, &service.id)
        .await?;

    assert!(fetched.is_some());
    let fetched = fetched.unwrap();
    assert_eq!(fetched.id, "service-get");
    assert_eq!(fetched.name().as_deref(), Some("glance"));
    assert_eq!(fetched.r#type.as_deref(), Some("image"));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_not_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let fetched = state
        .provider
        .get_catalog_provider()
        .get_service(&state, "does-not-exist")
        .await?;
    assert!(fetched.is_none());
    Ok(())
}
