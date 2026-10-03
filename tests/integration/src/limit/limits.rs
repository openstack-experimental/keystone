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
//! Test limits.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_config::LimitEnforcementModel;
use openstack_keystone_core::limit::LimitProviderError;
use openstack_keystone_core_types::limit::*;

use super::{domain_limit, exec, project_limit, registered, setup_region, setup_service};
use crate::common::{get_state, get_state_with_config};
use crate::{create_domain, create_project};

#[traced_test]
#[tokio::test]
async fn test_crud() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let region = setup_region(&state).await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    provider
        .create_registered_limits(
            &exec(&state),
            vec![registered(&service.id, Some(&region.id), "cores", 10)],
        )
        .await?;

    let mut data = project_limit(&service.id, Some(&region.id), "cores", &project.id, 5);
    data.description = Some("descr".into());
    let created = provider
        .create_limits(&exec(&state), vec![data])
        .await?
        .remove(0);
    assert!(!created.id.is_empty());
    assert_eq!(Some(project.id.clone()), created.project_id);
    assert_eq!(None, created.domain_id);
    assert_eq!(5, created.resource_limit);
    assert_eq!("cores", created.resource_name);
    assert_eq!(service.id, created.service_id);
    assert_eq!(Some(region.id.clone()), created.region_id);
    assert_eq!(Some("descr".to_string()), created.description);

    assert_eq!(
        Some(created.clone()),
        provider.get_limit(&exec(&state), &created.id).await?
    );

    // Zero is a valid value and the description can be reset.
    let updated = provider
        .update_limit(
            &exec(&state),
            &created.id,
            LimitUpdate {
                description: Some(None),
                resource_limit: Some(0),
            },
        )
        .await?;
    assert_eq!(0, updated.resource_limit);
    assert_eq!(None, updated.description);
    assert_eq!(created.project_id, updated.project_id);

    provider.delete_limit(&exec(&state), &created.id).await?;
    assert!(
        provider
            .get_limit(&exec(&state), &created.id)
            .await?
            .is_none()
    );
    assert!(matches!(
        provider.delete_limit(&exec(&state), &created.id).await,
        Err(LimitProviderError::LimitNotFound(_))
    ));
    assert!(matches!(
        provider
            .update_limit(
                &exec(&state),
                &created.id,
                LimitUpdate {
                    resource_limit: Some(1),
                    ..Default::default()
                }
            )
            .await,
        Err(LimitProviderError::LimitNotFound(_))
    ));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_domain_limit() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let domain = create_domain!(state)?;
    provider
        .create_registered_limits(
            &exec(&state),
            vec![registered(&service.id, None, "cores", 10)],
        )
        .await?;

    let created = provider
        .create_limits(
            &exec(&state),
            vec![domain_limit(&service.id, None, "cores", &domain.id, 7)],
        )
        .await?
        .remove(0);
    assert_eq!(Some(domain.id.clone()), created.domain_id);
    assert_eq!(None, created.project_id);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_project_acting_as_domain_is_normalized() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let domain = create_domain!(state)?;
    provider
        .create_registered_limits(
            &exec(&state),
            vec![registered(&service.id, None, "cores", 10)],
        )
        .await?;

    let created = provider
        .create_limits(
            &exec(&state),
            vec![project_limit(&service.id, None, "cores", &domain.id, 7)],
        )
        .await?
        .remove(0);
    assert_eq!(Some(domain.id.clone()), created.domain_id);
    assert_eq!(None, created.project_id);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_invalid_target() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    provider
        .create_registered_limits(
            &exec(&state),
            vec![registered(&service.id, None, "cores", 10)],
        )
        .await?;

    // Both project and domain.
    let mut both = project_limit(&service.id, None, "cores", &project.id, 1);
    both.domain_id = Some(domain.id.clone());
    assert!(matches!(
        provider.create_limits(&exec(&state), vec![both]).await,
        Err(LimitProviderError::InvalidReference(_))
    ));
    // Neither project nor domain.
    let mut neither = project_limit(&service.id, None, "cores", &project.id, 1);
    neither.project_id = None;
    assert!(matches!(
        provider.create_limits(&exec(&state), vec![neither]).await,
        Err(LimitProviderError::InvalidReference(_))
    ));
    // Unknown project and domain.
    assert!(matches!(
        provider
            .create_limits(
                &exec(&state),
                vec![project_limit(&service.id, None, "cores", "missing", 1)]
            )
            .await,
        Err(LimitProviderError::InvalidReference(_))
    ));
    assert!(matches!(
        provider
            .create_limits(
                &exec(&state),
                vec![domain_limit(&service.id, None, "cores", "missing", 1)]
            )
            .await,
        Err(LimitProviderError::InvalidReference(_))
    ));
    // Unknown service.
    assert!(matches!(
        provider
            .create_limits(
                &exec(&state),
                vec![project_limit("missing", None, "cores", &project.id, 1)]
            )
            .await,
        Err(LimitProviderError::InvalidReference(_))
    ));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_no_registered_limit() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let region = setup_region(&state).await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    provider
        .create_registered_limits(
            &exec(&state),
            vec![registered(&service.id, None, "cores", 10)],
        )
        .await?;

    // Unknown resource.
    assert!(matches!(
        provider
            .create_limits(
                &exec(&state),
                vec![project_limit(&service.id, None, "ram", &project.id, 1)]
            )
            .await,
        Err(LimitProviderError::NoLimitReference(_))
    ));
    // The region must match the registered limit exactly.
    assert!(matches!(
        provider
            .create_limits(
                &exec(&state),
                vec![project_limit(
                    &service.id,
                    Some(&region.id),
                    "cores",
                    &project.id,
                    1
                )]
            )
            .await,
        Err(LimitProviderError::NoLimitReference(_))
    ));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_duplicate_and_batch_atomicity() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let domain = create_domain!(state)?;
    let project1 = create_project!(state, domain.id.clone())?;
    let project2 = create_project!(state, domain.id.clone())?;
    provider
        .create_registered_limits(
            &exec(&state),
            vec![registered(&service.id, None, "cores", 10)],
        )
        .await?;
    provider
        .create_limits(
            &exec(&state),
            vec![project_limit(&service.id, None, "cores", &project1.id, 1)],
        )
        .await?;

    assert!(matches!(
        provider
            .create_limits(
                &exec(&state),
                vec![project_limit(&service.id, None, "cores", &project1.id, 2)]
            )
            .await,
        Err(LimitProviderError::Conflict(_))
    ));

    // The second item of the batch conflicts, therefore the first one must
    // not remain.
    assert!(matches!(
        provider
            .create_limits(
                &exec(&state),
                vec![
                    project_limit(&service.id, None, "cores", &project2.id, 2),
                    project_limit(&service.id, None, "cores", &project1.id, 2),
                ]
            )
            .await,
        Err(LimitProviderError::Conflict(_))
    ));
    assert!(
        provider
            .list_limits(
                &exec(&state),
                &LimitListParameters {
                    project_id: Some(project2.id.clone()),
                    ..Default::default()
                }
            )
            .await?
            .is_empty()
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_filters_and_pagination() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let region = setup_region(&state).await?;
    let domain = create_domain!(state)?;
    let project1 = create_project!(state, domain.id.clone())?;
    let project2 = create_project!(state, domain.id.clone())?;
    provider
        .create_registered_limits(
            &exec(&state),
            vec![
                registered(&service.id, None, "cores", 10),
                registered(&service.id, Some(&region.id), "cores", 10),
                registered(&service.id, None, "ram", 10),
            ],
        )
        .await?;
    provider
        .create_limits(
            &exec(&state),
            vec![
                project_limit(&service.id, None, "cores", &project1.id, 1),
                project_limit(&service.id, None, "ram", &project1.id, 2),
                project_limit(&service.id, Some(&region.id), "cores", &project1.id, 3),
                project_limit(&service.id, None, "cores", &project2.id, 4),
                domain_limit(&service.id, None, "cores", &domain.id, 5),
            ],
        )
        .await?;

    let list = |params: LimitListParameters| {
        let state = state.clone();
        async move {
            state
                .provider
                .get_limit_provider()
                .list_limits(&exec(&state), &params)
                .await
        }
    };
    assert_eq!(5, list(Default::default()).await?.len());
    assert_eq!(
        3,
        list(LimitListParameters {
            project_id: Some(project1.id.clone()),
            ..Default::default()
        })
        .await?
        .len()
    );
    assert_eq!(
        1,
        list(LimitListParameters {
            domain_id: Some(domain.id.clone()),
            ..Default::default()
        })
        .await?
        .len()
    );
    assert_eq!(
        1,
        list(LimitListParameters {
            region_id: Some(region.id.clone()),
            ..Default::default()
        })
        .await?
        .len()
    );
    assert_eq!(
        1,
        list(LimitListParameters {
            project_id: Some(project1.id.clone()),
            resource_name: Some("ram".into()),
            ..Default::default()
        })
        .await?
        .len()
    );
    assert!(
        list(LimitListParameters {
            service_id: Some("unknown".into()),
            ..Default::default()
        })
        .await?
        .is_empty()
    );

    let page1 = list(LimitListParameters {
        pagination: openstack_keystone_core_types::ListPagination {
            limit: Some(2),
            ..Default::default()
        },
        ..Default::default()
    })
    .await?;
    assert_eq!(3, page1.len());
    let page2 = list(LimitListParameters {
        pagination: openstack_keystone_core_types::ListPagination {
            limit: Some(2),
            marker: Some(page1[1].id.clone()),
            ..Default::default()
        },
        ..Default::default()
    })
    .await?;
    assert_eq!(3, page2.len());
    assert_eq!(page1[2].id, page2[0].id);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_delete_by_project_and_domain() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    provider
        .create_registered_limits(
            &exec(&state),
            vec![registered(&service.id, None, "cores", 10)],
        )
        .await?;
    provider
        .create_limits(
            &exec(&state),
            vec![
                project_limit(&service.id, None, "cores", &project.id, 1),
                domain_limit(&service.id, None, "cores", &domain.id, 5),
            ],
        )
        .await?;

    provider
        .delete_limits_by_project(&exec(&state), &project.id)
        .await?;
    let left = provider
        .list_limits(&exec(&state), &LimitListParameters::default())
        .await?;
    assert_eq!(1, left.len());
    assert_eq!(Some(domain.id.clone()), left[0].domain_id);

    provider
        .delete_limits_by_domain(&exec(&state), &domain.id)
        .await?;
    assert!(
        provider
            .list_limits(&exec(&state), &LimitListParameters::default())
            .await?
            .is_empty()
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_strict_two_level() -> Result<()> {
    let (state, _tmp) = get_state_with_config(|cfg| {
        cfg.limit.enforcement_model = LimitEnforcementModel::StrictTwoLevel;
    })
    .await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    provider
        .create_registered_limits(
            &exec(&state),
            vec![registered(&service.id, None, "cores", 10)],
        )
        .await?;

    // Without the domain limit the registered default of the parent applies.
    assert!(matches!(
        provider
            .create_limits(
                &exec(&state),
                vec![project_limit(&service.id, None, "cores", &project.id, 11)]
            )
            .await,
        Err(LimitProviderError::InvalidLimit(_))
    ));
    let project_limit_ref = provider
        .create_limits(
            &exec(&state),
            vec![project_limit(&service.id, None, "cores", &project.id, 8)],
        )
        .await?
        .remove(0);

    // Domain limit may not be below the limit of its project.
    assert!(matches!(
        provider
            .create_limits(
                &exec(&state),
                vec![domain_limit(&service.id, None, "cores", &domain.id, 7)]
            )
            .await,
        Err(LimitProviderError::InvalidLimit(_))
    ));
    let domain_limit_ref = provider
        .create_limits(
            &exec(&state),
            vec![domain_limit(&service.id, None, "cores", &domain.id, 9)],
        )
        .await?
        .remove(0);

    // Project limit can not be raised over the domain limit.
    assert!(matches!(
        provider
            .update_limit(
                &exec(&state),
                &project_limit_ref.id,
                LimitUpdate {
                    resource_limit: Some(10),
                    ..Default::default()
                }
            )
            .await,
        Err(LimitProviderError::InvalidLimit(_))
    ));
    // Domain limit can not be lowered under the limit of the project.
    assert!(matches!(
        provider
            .update_limit(
                &exec(&state),
                &domain_limit_ref.id,
                LimitUpdate {
                    resource_limit: Some(5),
                    ..Default::default()
                }
            )
            .await,
        Err(LimitProviderError::InvalidLimit(_))
    ));
    // Valid changes pass.
    provider
        .update_limit(
            &exec(&state),
            &project_limit_ref.id,
            LimitUpdate {
                resource_limit: Some(9),
                ..Default::default()
            },
        )
        .await?;
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_strict_two_level_regions_are_isolated() -> Result<()> {
    let (state, _tmp) = get_state_with_config(|cfg| {
        cfg.limit.enforcement_model = LimitEnforcementModel::StrictTwoLevel;
    })
    .await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let region = setup_region(&state).await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    provider
        .create_registered_limits(
            &exec(&state),
            vec![
                registered(&service.id, None, "cores", 100),
                registered(&service.id, Some(&region.id), "cores", 100),
            ],
        )
        .await?;

    // The regional project limit and the global domain limit refer to
    // different registered limits.
    provider
        .create_limits(
            &exec(&state),
            vec![project_limit(
                &service.id,
                Some(&region.id),
                "cores",
                &project.id,
                50,
            )],
        )
        .await?;
    // The global domain limit is not constrained by the regional project
    // limit, even when it is smaller.
    provider
        .create_limits(
            &exec(&state),
            vec![domain_limit(&service.id, None, "cores", &domain.id, 10)],
        )
        .await?;

    // The regional domain limit is constrained by the regional project limit.
    assert!(matches!(
        provider
            .create_limits(
                &exec(&state),
                vec![domain_limit(
                    &service.id,
                    Some(&region.id),
                    "cores",
                    &domain.id,
                    10
                )]
            )
            .await,
        Err(LimitProviderError::InvalidLimit(_))
    ));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_strict_two_level_batch() -> Result<()> {
    let (state, _tmp) = get_state_with_config(|cfg| {
        cfg.limit.enforcement_model = LimitEnforcementModel::StrictTwoLevel;
    })
    .await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    provider
        .create_registered_limits(
            &exec(&state),
            vec![registered(&service.id, None, "cores", 100)],
        )
        .await?;

    // The project limit is validated against the domain limit of the batch.
    assert!(matches!(
        provider
            .create_limits(
                &exec(&state),
                vec![
                    domain_limit(&service.id, None, "cores", &domain.id, 5),
                    project_limit(&service.id, None, "cores", &project.id, 6),
                ]
            )
            .await,
        Err(LimitProviderError::InvalidLimit(_))
    ));
    provider
        .create_limits(
            &exec(&state),
            vec![
                domain_limit(&service.id, None, "cores", &domain.id, 5),
                project_limit(&service.id, None, "cores", &project.id, 5),
            ],
        )
        .await?;
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_flat_model_ignores_hierarchy() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_limit_provider();
    let service = setup_service(&state).await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    provider
        .create_registered_limits(
            &exec(&state),
            vec![registered(&service.id, None, "cores", 10)],
        )
        .await?;
    provider
        .create_limits(
            &exec(&state),
            vec![
                domain_limit(&service.id, None, "cores", &domain.id, 5),
                project_limit(&service.id, None, "cores", &project.id, 50),
            ],
        )
        .await?;
    Ok(())
}
