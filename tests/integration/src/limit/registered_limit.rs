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
//! Test registered limits.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::limit::LimitProviderError;
use openstack_keystone_core_types::limit::*;

use super::{exec, project_limit, registered, setup_region, setup_service};
use crate::common::get_state;
use crate::{create_domain, create_project};

#[traced_test]
#[tokio::test]
async fn test_crud() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let region = setup_region(&state).await?;

    let mut data = registered(&service.id, Some(&region.id), "cores", 10);
    data.description = Some("cpu cores".into());
    let created = provider
        .create_registered_limits(&exec(&state), vec![data])
        .await?;
    assert_eq!(1, created.len());
    let reg = &created[0];
    assert!(!reg.id.is_empty());
    assert_eq!(10, reg.default_limit);
    assert_eq!(Some(region.id.clone()), reg.region_id);
    assert_eq!("cores", reg.resource_name);
    assert_eq!(service.id, reg.service_id);
    assert_eq!(Some("cpu cores".to_string()), reg.description);

    let fetched = provider
        .get_registered_limit(&exec(&state), &reg.id)
        .await?
        .expect("registered limit exists");
    assert_eq!(*reg, fetched);

    let updated = provider
        .update_registered_limit(
            &exec(&state),
            &reg.id,
            RegisteredLimitUpdate {
                default_limit: Some(0),
                description: Some(None),
                region_id: Some(None),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(0, updated.default_limit);
    assert_eq!(None, updated.description);
    assert_eq!(None, updated.region_id);
    assert_eq!("cores", updated.resource_name);

    provider
        .delete_registered_limit(&exec(&state), &reg.id)
        .await?;
    assert!(
        provider
            .get_registered_limit(&exec(&state), &reg.id)
            .await?
            .is_none()
    );
    assert!(matches!(
        provider
            .delete_registered_limit(&exec(&state), &reg.id)
            .await,
        Err(LimitProviderError::RegisteredLimitNotFound(_))
    ));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_not_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    assert!(matches!(
        state
            .provider
            .get_limit_provider()
            .update_registered_limit(
                &exec(&state),
                "missing",
                RegisteredLimitUpdate {
                    default_limit: Some(1),
                    ..Default::default()
                }
            )
            .await,
        Err(LimitProviderError::RegisteredLimitNotFound(_))
    ));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_unknown_references() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;

    assert!(matches!(
        provider
            .create_registered_limits(
                &exec(&state),
                vec![registered("missing-service", None, "cores", 1)]
            )
            .await,
        Err(LimitProviderError::InvalidReference(_))
    ));
    assert!(matches!(
        provider
            .create_registered_limits(
                &exec(&state),
                vec![registered(&service.id, Some("missing-region"), "cores", 1)]
            )
            .await,
        Err(LimitProviderError::InvalidReference(_))
    ));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_invalid_value() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let service = setup_service(&state).await?;
    assert!(matches!(
        state
            .provider
            .get_limit_provider()
            .create_registered_limits(
                &exec(&state),
                vec![registered(&service.id, None, "cores", -2)]
            )
            .await,
        Err(LimitProviderError::Validation { .. })
    ));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_duplicate_and_null_region() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let region = setup_region(&state).await?;

    provider
        .create_registered_limits(
            &exec(&state),
            vec![registered(&service.id, None, "cores", 1)],
        )
        .await?;
    // The same resource for a region is not a duplicate of the global one.
    provider
        .create_registered_limits(
            &exec(&state),
            vec![registered(&service.id, Some(&region.id), "cores", 2)],
        )
        .await?;
    // Both are duplicates of themselves.
    assert!(matches!(
        provider
            .create_registered_limits(
                &exec(&state),
                vec![registered(&service.id, None, "cores", 3)]
            )
            .await,
        Err(LimitProviderError::Conflict(_))
    ));
    assert!(matches!(
        provider
            .create_registered_limits(
                &exec(&state),
                vec![registered(&service.id, Some(&region.id), "cores", 3)]
            )
            .await,
        Err(LimitProviderError::Conflict(_))
    ));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_batch_is_atomic() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;

    // The second item duplicates the first one.
    assert!(matches!(
        provider
            .create_registered_limits(
                &exec(&state),
                vec![
                    registered(&service.id, None, "cores", 1),
                    registered(&service.id, None, "cores", 2),
                ]
            )
            .await,
        Err(LimitProviderError::Conflict(_))
    ));
    assert!(
        provider
            .list_registered_limits(&exec(&state), &RegisteredLimitListParameters::default())
            .await?
            .is_empty(),
        "nothing must be created"
    );

    let created = provider
        .create_registered_limits(
            &exec(&state),
            vec![
                registered(&service.id, None, "cores", 1),
                registered(&service.id, None, "ram", 2),
            ],
        )
        .await?;
    assert_eq!(2, created.len());
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_conflict() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let created = provider
        .create_registered_limits(
            &exec(&state),
            vec![
                registered(&service.id, None, "cores", 1),
                registered(&service.id, None, "ram", 2),
            ],
        )
        .await?;
    assert!(matches!(
        provider
            .update_registered_limit(
                &exec(&state),
                &created[1].id,
                RegisteredLimitUpdate {
                    resource_name: Some("cores".into()),
                    ..Default::default()
                }
            )
            .await,
        Err(LimitProviderError::Conflict(_))
    ));
    // Update which does not change the identity of the entry is fine.
    provider
        .update_registered_limit(
            &exec(&state),
            &created[1].id,
            RegisteredLimitUpdate {
                resource_name: Some("ram".into()),
                default_limit: Some(5),
                ..Default::default()
            },
        )
        .await?;
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_filters_and_pagination() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service1 = setup_service(&state).await?;
    let service2 = setup_service(&state).await?;
    let region = setup_region(&state).await?;
    provider
        .create_registered_limits(
            &exec(&state),
            vec![
                registered(&service1.id, None, "cores", 1),
                registered(&service1.id, Some(&region.id), "cores", 1),
                registered(&service1.id, None, "ram", 1),
                registered(&service2.id, None, "cores", 1),
            ],
        )
        .await?;

    let list = |params: RegisteredLimitListParameters| {
        let state = state.clone();
        async move {
            state
                .provider
                .get_limit_provider()
                .list_registered_limits(&exec(&state), &params)
                .await
        }
    };
    assert_eq!(4, list(Default::default()).await?.len());
    assert_eq!(
        3,
        list(RegisteredLimitListParameters {
            service_id: Some(service1.id.clone()),
            ..Default::default()
        })
        .await?
        .len()
    );
    assert_eq!(
        2,
        list(RegisteredLimitListParameters {
            resource_name: Some("cores".into()),
            service_id: Some(service1.id.clone()),
            ..Default::default()
        })
        .await?
        .len()
    );
    assert_eq!(
        1,
        list(RegisteredLimitListParameters {
            region_id: Some(region.id.clone()),
            ..Default::default()
        })
        .await?
        .len()
    );

    // Pagination over-fetches one row.
    let page1 = list(RegisteredLimitListParameters {
        pagination: openstack_keystone_core_types::ListPagination {
            limit: Some(2),
            ..Default::default()
        },
        ..Default::default()
    })
    .await?;
    assert_eq!(3, page1.len());
    let page2 = list(RegisteredLimitListParameters {
        pagination: openstack_keystone_core_types::ListPagination {
            limit: Some(2),
            marker: Some(page1[1].id.clone()),
            ..Default::default()
        },
        ..Default::default()
    })
    .await?;
    assert_eq!(2, page2.len());
    assert_eq!(page1[2].id, page2[0].id);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_referenced_registered_limit_is_protected() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let reg = provider
        .create_registered_limits(
            &exec(&state),
            vec![registered(&service.id, None, "cores", 10)],
        )
        .await?
        .remove(0);
    let limit = provider
        .create_limits(
            &exec(&state),
            vec![project_limit(&service.id, None, "cores", &project.id, 5)],
        )
        .await?
        .remove(0);

    assert!(matches!(
        provider
            .delete_registered_limit(&exec(&state), &reg.id)
            .await,
        Err(LimitProviderError::RegisteredLimitInUse(_))
    ));
    assert!(matches!(
        provider
            .update_registered_limit(
                &exec(&state),
                &reg.id,
                RegisteredLimitUpdate {
                    default_limit: Some(1),
                    ..Default::default()
                }
            )
            .await,
        Err(LimitProviderError::RegisteredLimitInUse(_))
    ));

    provider.delete_limit(&exec(&state), &limit.id).await?;
    provider
        .delete_registered_limit(&exec(&state), &reg.id)
        .await?;
    Ok(())
}
