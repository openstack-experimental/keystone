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

use test_api::credential::create_credential;
use test_api::guard::ResourceGuard;

#[tokio::test]
#[traced_test]
async fn test_create_totp_credential() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let blob = format!(r#"{{"seed":"{}"}}"#, Uuid::new_v4().simple());

    let guard = create_credential(
        &tc,
        CredentialCreateBuilder::default()
            .blob(blob.clone())
            .r#type("totp")
            .build()?,
    )
    .await?;

    assert_eq!(guard.blob, blob);
    assert_eq!(guard.r#type, "totp");
    assert!(!guard.id.is_empty());
    assert!(!guard.user_id.is_empty());

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_defaults_user_id_to_caller() -> Result<()> {
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

    // `user_id` was omitted; the server must default it to the caller.
    assert!(!guard.user_id.is_empty());

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_ec2_without_project_id_fails() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let blob = format!(r#"{{"access":"{}"}}"#, Uuid::new_v4().simple());

    let result = create_credential(
        &tc,
        CredentialCreateBuilder::default()
            .blob(blob)
            .r#type("ec2")
            .build()?,
    )
    .await;

    assert!(
        result.is_err(),
        "ec2 credentials without project_id must be rejected"
    );
    Ok(())
}
