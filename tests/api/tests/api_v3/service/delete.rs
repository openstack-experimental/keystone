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

use openstack_keystone_api_types::v3::service::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::guard::ResourceGuard;
use test_api::service::{create_service, show_service};

#[tokio::test]
#[traced_test]
async fn test_delete_service() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let name = format!("service_{}", Uuid::new_v4().simple());

    let guard = create_service(
        &tc,
        ServiceCreateBuilder::default()
            .r#type("identity-rs")
            .name(name)
            .enabled(true)
            .build()?,
    )
    .await?;
    let id = guard.id.clone();

    guard.delete().await?;

    let result = show_service(&tc, &id).await;
    assert!(result.is_err(), "service must be gone after deletion");
    Ok(())
}
