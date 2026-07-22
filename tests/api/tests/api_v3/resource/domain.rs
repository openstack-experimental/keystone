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
use uuid::Uuid;

use openstack_keystone_api_types::v3::domain::*;
use openstack_sdk::AsyncOpenStack;

use test_api::guard::ResourceGuard;
use test_api::resource::domain::*;
use test_api::resource::*;

#[tokio::test]
async fn test_domain_create() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_domain(
        &test_client,
        DomainCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .build()?,
    )
    .await?;
    assert!(!domain.id.is_empty(), "domain id should not be empty");
    assert!(domain.enabled, "domain should be enabled by default");
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_domain_show() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_domain(
        &test_client,
        DomainCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .build()?,
    )
    .await?;
    let shown = get_domain(&test_client, &domain.id)
        .await?
        .expect("domain must be found");
    assert_eq!(shown.id, domain.id);
    assert_eq!(shown.name, domain.name);
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_domain_list() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_domain(
        &test_client,
        DomainCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .build()?,
    )
    .await?;
    let params = DomainListRequest {
        ids: Some(domain.id.clone()),
        name: None,
    };
    let domains = list_domains(&test_client, params).await?;
    assert!(
        !domains.is_empty(),
        "domain list should contain the created domain"
    );
    assert_eq!(domains[0].id, domain.id);
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_domain_update() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_domain(
        &test_client,
        DomainCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .build()?,
    )
    .await?;
    let updated = update_domain(
        &test_client,
        &domain.id,
        DomainUpdateBuilder::default()
            .name("updated_name")
            .enabled(false)
            .build()?,
    )
    .await?;
    assert_eq!(updated.name, "updated_name");
    assert!(!updated.enabled);

    let shown = get_domain(&test_client, &domain.id)
        .await?
        .expect("domain must be found");
    assert_eq!(shown.name, "updated_name");
    assert!(!shown.enabled);

    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_domain_delete() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_domain(
        &test_client,
        DomainCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .build()?,
    )
    .await?;
    delete_domain(&test_client, &domain.id).await?;
    let result = get_domain(&test_client, &domain.id).await;
    assert!(result.is_err(), "domain should be deleted");
    Ok(())
}
