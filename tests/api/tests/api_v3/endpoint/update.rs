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

use test_api::endpoint::{create_endpoint, show_endpoint, update_endpoint};
use test_api::guard::ResourceGuard;
use test_api::service::create_service;

#[tokio::test]
#[traced_test]
async fn test_update_url() -> Result<()> {
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

    let old_url = format!("https://example.com/{}", Uuid::new_v4().simple());
    let new_url = format!("https://example.com/{}", Uuid::new_v4().simple());

    let endpoint_guard = create_endpoint(
        &tc,
        EndpointCreateBuilder::default()
            .interface("public")
            .service_id(service_guard.id.clone())
            .url(old_url)
            .enabled(true)
            .build()?,
    )
    .await?;

    let updated = update_endpoint(
        &tc,
        &endpoint_guard.id,
        EndpointUpdateBuilder::default()
            .url(new_url.clone())
            .build()?,
    )
    .await?;

    assert_eq!(updated.id, endpoint_guard.id);
    assert_eq!(updated.url, new_url);

    // Re-fetch to verify the change is persisted, not just echoed back.
    let fetched = show_endpoint(&tc, &endpoint_guard.id).await?;
    assert_eq!(fetched.url, new_url);

    endpoint_guard.delete().await?;
    service_guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_missing_endpoint_fails() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let result = update_endpoint(
        &tc,
        format!("missing-{}", Uuid::new_v4().simple()),
        EndpointUpdateBuilder::default().enabled(false).build()?,
    )
    .await;

    assert!(result.is_err(), "updating a missing endpoint must fail");
    Ok(())
}
