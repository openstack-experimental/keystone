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

use openstack_keystone_api_types::v3::credential::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::credential::{create_credential, list_credentials};
use test_api::guard::ResourceGuard;

#[tokio::test]
#[traced_test]
async fn test_list_includes_created_credential() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let blob = format!(r#"{{"seed":"{}"}}"#, Uuid::new_v4().simple());

    let guard = create_credential(
        &tc,
        CredentialCreateBuilder::default()
            .blob(blob)
            .r#type("totp")
            .build()?,
    )
    .await?;

    let all = list_credentials(&tc, None, None).await?;
    assert!(
        all.iter().any(|c| c.id == guard.id),
        "created credential must appear in the unfiltered list"
    );

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_filtered_by_type_excludes_other_types() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let blob = format!(r#"{{"seed":"{}"}}"#, Uuid::new_v4().simple());
    let marker_type = format!("custom-{}", Uuid::new_v4().simple());

    let guard = create_credential(
        &tc,
        CredentialCreateBuilder::default()
            .blob(blob)
            .r#type(marker_type.clone())
            .build()?,
    )
    .await?;

    let filtered = list_credentials(&tc, Some(&marker_type), None).await?;
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].id, guard.id);

    let other = list_credentials(&tc, Some("totp"), None).await?;
    assert!(!other.iter().any(|c| c.id == guard.id));

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_filtered_by_user_id() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let blob = format!(r#"{{"seed":"{}"}}"#, Uuid::new_v4().simple());

    let guard = create_credential(
        &tc,
        CredentialCreateBuilder::default()
            .blob(blob)
            .r#type("totp")
            .build()?,
    )
    .await?;

    let filtered = list_credentials(&tc, None, Some(&guard.user_id)).await?;
    assert!(filtered.iter().all(|c| c.user_id == guard.user_id));
    assert!(filtered.iter().any(|c| c.id == guard.id));

    guard.delete().await?;
    Ok(())
}
