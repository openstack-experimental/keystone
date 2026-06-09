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
//! Test listing services.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::catalog::CatalogApi;
use openstack_keystone_core_types::catalog::{ServiceCreate, ServiceListParameters};

use crate::catalog::create_service;
use crate::common::get_state;

fn service(id: &str, r#type: &str) -> ServiceCreate {
    ServiceCreate {
        enabled: true,
        extra: HashMap::new(),
        id: Some(id.to_string()),
        r#type: Some(r#type.to_string()),
    }
}

#[traced_test]
#[tokio::test]
async fn test_list() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let _s1 = create_service(&state, service("list-s1", "compute")).await?;
    let _s2 = create_service(&state, service("list-s2", "image")).await?;

    let services = state
        .provider
        .get_catalog_provider()
        .list_services(&state, &ServiceListParameters::default())
        .await?;

    let ids: Vec<&str> = services.iter().map(|s| s.id.as_str()).collect();
    assert!(ids.contains(&"list-s1"));
    assert!(ids.contains(&"list-s2"));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_filter_by_type() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let _c1 = create_service(&state, service("compute-1", "compute")).await?;
    let _c2 = create_service(&state, service("compute-2", "compute")).await?;
    let _i1 = create_service(&state, service("image-1", "image")).await?;

    let services = state
        .provider
        .get_catalog_provider()
        .list_services(
            &state,
            &ServiceListParameters {
                name: None,
                r#type: Some("compute".to_string()),
            },
        )
        .await?;

    let ids: Vec<&str> = services.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(services.len(), 2, "expected only the two compute services");
    assert!(ids.contains(&"compute-1"));
    assert!(ids.contains(&"compute-2"));
    Ok(())
}
