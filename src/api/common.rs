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
//! Common API helpers
use crate::api::error::KeystoneApiError;
use crate::api::types::ProjectScope;
use crate::keystone::ServiceState;
use crate::resource::{
    ResourceApi,
    types::{Domain, Project},
};

/// Get the domain by ID or Name
///
/// # Arguments
/// * `state` - The service state
/// * `id` - The domain ID
/// * `name` - The domain name
///
/// # Returns
/// * `Result<Domain, KeystoneApiError>` - The domain object
pub async fn get_domain<I: AsRef<str>, N: AsRef<str>>(
    state: &ServiceState,
    id: Option<I>,
    name: Option<N>,
) -> Result<Domain, KeystoneApiError> {
    if let Some(did) = &id {
        state
            .provider
            .get_resource_provider()
            .get_domain(state, did.as_ref())
            .await?
            .ok_or_else(|| KeystoneApiError::NotFound {
                resource: "domain".into(),
                identifier: did.as_ref().to_string(),
            })
    } else if let Some(name) = &name {
        state
            .provider
            .get_resource_provider()
            .find_domain_by_name(state, name.as_ref())
            .await?
            .ok_or_else(|| KeystoneApiError::NotFound {
                resource: "domain".into(),
                identifier: name.as_ref().to_string(),
            })
    } else {
        Err(KeystoneApiError::DomainIdOrName)
    }
}

/// Find the project referred in the scope.
///
/// # Arguments
/// * `state` - The service state.
/// * `scope` - The scope to find the project.
///
/// # Returns
/// The resolved project.
pub async fn find_project_from_scope(
    state: &ServiceState,
    scope: &ProjectScope,
) -> Result<Option<Project>, KeystoneApiError> {
    let project = if let Some(pid) = &scope.id {
        state
            .provider
            .get_resource_provider()
            .get_project(state, pid)
            .await?
    } else if let Some(name) = &scope.name {
        if let Some(domain) = &scope.domain {
            let domain_id = match &domain.id {
                Some(id) => id.clone(),
                None => {
                    state
                        .provider
                        .get_resource_provider()
                        .find_domain_by_name(
                            state,
                            &domain
                                .name
                                .clone()
                                .ok_or(KeystoneApiError::DomainIdOrName)?,
                        )
                        .await?
                        .ok_or(KeystoneApiError::NotFound {
                            resource: "domain".to_string(),
                            identifier: domain
                                .name
                                .clone()
                                .ok_or(KeystoneApiError::DomainIdOrName)?,
                        })?
                        .id
                }
            };
            state
                .provider
                .get_resource_provider()
                .get_project_by_name(state, name, &domain_id)
                .await?
        } else {
            return Err(KeystoneApiError::ProjectDomain);
        }
    } else {
        return Err(KeystoneApiError::ProjectIdOrName);
    };
    Ok(project)
}

#[cfg(test)]
mod tests {
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;

    use super::*;

    use crate::config::Config;

    use crate::keystone::Service;
    use crate::policy::MockPolicyFactory;
    use crate::provider::Provider;
    use crate::resource::{MockResourceProvider, types::Domain};

    #[tokio::test]
    async fn test_get_domain() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "domain_id")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "domain_id".into(),
                    name: "domain_name".into(),
                    ..Default::default()
                }))
            });
        resource_mock
            .expect_find_domain_by_name()
            .withf(|_, id: &'_ str| id == "domain_name")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "domain_id".into(),
                    name: "domain_name".into(),
                    ..Default::default()
                }))
            });
        let provider = Provider::mocked_builder()
            .resource(resource_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );

        assert_eq!(
            "domain_id",
            get_domain(&state, Some("domain_id"), None::<&str>)
                .await
                .unwrap()
                .id
        );
        assert_eq!(
            "domain_id",
            get_domain(&state, None::<&str>, Some("domain_name"))
                .await
                .unwrap()
                .id
        );
        assert_eq!(
            "domain_id",
            get_domain(&state, Some("domain_id"), Some("other_domain_name"))
                .await
                .unwrap()
                .id
        );
        match get_domain(&state, None::<&str>, None::<&str>).await {
            Err(KeystoneApiError::DomainIdOrName) => {}
            _ => {
                panic!("wrong result");
            }
        }
    }
}
