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
//! Live-OPA `/v4/scim_realms` CRUD (ADR 0024 §2). Exercises
//! `policy/identity/scim_realm/*.rego` against the real policy engine,
//! complementing `tests/integration/src/scim_realm`'s mocked-policy,
//! real-backend coverage.

use eyre::Result;
use std::sync::Arc;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v4::scim_realm::ScimRealmUpdate;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::federation::identity_provider::*;
use test_api::guard::*;
use test_api::scim_realm::*;

#[tokio::test]
#[traced_test]
async fn test_create_show_update_roundtrip() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let idp = create_identity_provider(
        &test_client,
        sample_identity_provider_create(
            "default",
            &format!("scim-realm-api-test-{}", Uuid::new_v4().simple()),
        ),
    )
    .await?;

    let provider_id = format!("scim-realm-api-test-{}", Uuid::new_v4().simple());
    let created = create_realm(
        &test_client,
        sample_realm_create("default", &provider_id, &idp.id),
    )
    .await?;
    assert_eq!(created.domain_id, "default");
    assert_eq!(created.provider_id, provider_id);
    assert!(created.enabled);

    let shown = show_realm(&test_client, "default", &provider_id).await?;
    assert_eq!(shown, created);

    let listed = list_realms(
        &test_client,
        ScimRealmListParameters {
            domain_id: "default".to_string(),
            enabled: Some(true),
        },
    )
    .await?;
    assert!(listed.iter().any(|r| r.provider_id == provider_id));

    let updated = update_realm(
        &test_client,
        "default",
        &provider_id,
        ScimRealmUpdate {
            display_name: Some("renamed by test_api".to_string()),
            enabled: Some(false),
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(updated.display_name, "renamed by test_api");
    assert!(!updated.enabled);

    let listed_enabled_only = list_realms(
        &test_client,
        ScimRealmListParameters {
            domain_id: "default".to_string(),
            enabled: Some(true),
        },
    )
    .await?;
    assert!(
        !listed_enabled_only
            .iter()
            .any(|r| r.provider_id == provider_id)
    );

    idp.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_rejects_unresolvable_idp() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let provider_id = format!("scim-realm-api-test-{}", Uuid::new_v4().simple());
    let result = create_realm(
        &test_client,
        sample_realm_create("default", &provider_id, "never-registered-idp"),
    )
    .await;

    assert!(
        result.is_err(),
        "creating a realm against an unresolvable idp_id must fail"
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_purge_not_found_resource() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let idp = create_identity_provider(
        &test_client,
        sample_identity_provider_create(
            "default",
            &format!("scim-realm-api-test-{}", Uuid::new_v4().simple()),
        ),
    )
    .await?;
    let provider_id = format!("scim-realm-api-test-{}", Uuid::new_v4().simple());
    create_realm(
        &test_client,
        sample_realm_create("default", &provider_id, &idp.id),
    )
    .await?;

    let result = purge_resource(
        &test_client,
        "default",
        &provider_id,
        "user",
        "never-provisioned-user-id",
    )
    .await;
    assert!(
        result.is_err(),
        "purging a resource with no SCIM index anchor must fail"
    );

    idp.delete().await?;
    Ok(())
}
