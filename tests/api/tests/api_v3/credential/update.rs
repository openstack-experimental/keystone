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

use test_api::credential::{create_credential, show_credential, update_credential};
use test_api::guard::ResourceGuard;

#[tokio::test]
#[traced_test]
async fn test_update_blob() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let old_blob = format!(r#"{{"seed":"{}"}}"#, Uuid::new_v4().simple());
    let new_blob = format!(r#"{{"seed":"{}"}}"#, Uuid::new_v4().simple());

    let guard = create_credential(
        &tc,
        CredentialCreateBuilder::default()
            .blob(old_blob)
            .r#type("totp")
            .build()?,
    )
    .await?;

    let updated = update_credential(
        &tc,
        &guard.id,
        CredentialUpdateBuilder::default()
            .blob(new_blob.clone())
            .build()?,
    )
    .await?;

    assert_eq!(updated.id, guard.id);
    assert_eq!(updated.blob, new_blob);

    // Re-fetch to verify the change is persisted, not just echoed back.
    let fetched = show_credential(&tc, &guard.id).await?;
    assert_eq!(fetched.blob, new_blob);

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_type() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let blob = format!(r#"{{"seed":"{}"}}"#, Uuid::new_v4().simple());
    let new_type = format!("custom-{}", Uuid::new_v4().simple());

    let guard = create_credential(
        &tc,
        CredentialCreateBuilder::default()
            .blob(blob.clone())
            .r#type("totp")
            .build()?,
    )
    .await?;

    let updated = update_credential(
        &tc,
        &guard.id,
        CredentialUpdateBuilder::default()
            .r#type(new_type.clone())
            .build()?,
    )
    .await?;

    assert_eq!(updated.r#type, new_type);
    // Untouched field must survive the partial update.
    assert_eq!(updated.blob, blob);

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_missing_credential_fails() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let result = update_credential(
        &tc,
        format!("missing-{}", Uuid::new_v4().simple()),
        CredentialUpdateBuilder::default().r#type("totp").build()?,
    )
    .await;

    assert!(result.is_err(), "updating a missing credential must fail");
    Ok(())
}
