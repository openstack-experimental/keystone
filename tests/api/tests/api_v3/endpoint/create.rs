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

use std::sync::Arc;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v3::endpoint::*;
use openstack_keystone_api_types::v3::service::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::endpoint::create_endpoint;
use test_api::guard::ResourceGuard;
use test_api::service::create_service;

#[tokio::test]
#[traced_test]
async fn test_create_endpoint() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let service_name = format!("service_{}", Uuid::new_v4().simple());

    let service_guard = create_service(
        &tc,
        ServiceCreateBuilder::default()
            .r#type("identity-rs")
            .name(service_name)
            .enabled(true)
            .build()?,
    )
    .await?;

    let url = format!("https://example.com/{}", Uuid::new_v4().simple());
    let endpoint_guard = create_endpoint(
        &tc,
        EndpointCreateBuilder::default()
            .interface("public")
            .service_id(service_guard.id.clone())
            .url(url.clone())
            .enabled(true)
            .build()?,
    )
    .await?;

    assert_eq!(endpoint_guard.service_id, service_guard.id);
    assert_eq!(endpoint_guard.interface, "public");
    assert_eq!(endpoint_guard.url, url);
    assert!(!endpoint_guard.id.is_empty());

    endpoint_guard.delete().await?;
    service_guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_endpoint_missing_service_fails() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let url = format!("https://example.com/{}", Uuid::new_v4().simple());

    let result = create_endpoint(
        &tc,
        EndpointCreateBuilder::default()
            .interface("public")
            .service_id(format!("missing-{}", Uuid::new_v4().simple()))
            .url(url)
            .enabled(true)
            .build()?,
    )
    .await;

    assert!(
        result.is_err(),
        "creating an endpoint for a missing service must fail"
    );
    Ok(())
}
