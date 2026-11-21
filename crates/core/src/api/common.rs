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
//! # Common API helpers
use openstack_keystone_core_types::auth::ScopeInfo;

use openstack_keystone_api_types::error::KeystoneApiError;
use openstack_keystone_api_types::scope::{ProjectBuilder, ScopeProject};
use openstack_keystone_core_types::resource::{Domain, Project};
use openstack_keystone_core_types::scope::Scope as ProviderScope;

use crate::auth::ExecutionContext;
use crate::keystone::ServiceState;

/// Get the scope [ProjectBuilder] for the given Project.
///
/// # Arguments
/// * `state` - The service state
/// * `project` - The project to get info for
/// * `user_domain` - The user's domain
///
/// # Returns
/// * `Result<ProjectBuilder, KeystoneApiError>` - The project builder
#[allow(dead_code)]
pub(super) async fn get_project_info_scope_builder(
    state: &ServiceState,
    project: &Project,
    user_domain: &Domain,
) -> Result<ProjectBuilder, KeystoneApiError> {
    let mut project_response = ProjectBuilder::default();
    project_response.id(project.id.clone());
    project_response.name(project.name.clone());
    if project.domain_id == user_domain.id {
        project_response.domain(user_domain.clone());
    } else {
        let project_domain = get_domain(state, Some(&project.domain_id), None::<&str>).await?;
        project_response.domain(project_domain.clone());
    }
    Ok(project_response)
}

/// Get the domain by ID or Name.
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
        let exec = ExecutionContext::internal(state);
        state
            .provider
            .get_resource_provider()
            .get_domain(&exec, did.as_ref())
            .await?
            .ok_or_else(|| KeystoneApiError::NotFound {
                resource: "domain".into(),
                identifier: did.as_ref().to_string(),
            })
    } else if let Some(name) = &name {
        let exec = ExecutionContext::internal(state);
        state
            .provider
            .get_resource_provider()
            .find_domain_by_name(&exec, name.as_ref())
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
/// * `Result<Option<Project>, KeystoneApiError>` - The resolved project or None
///   if not found
pub async fn find_project_from_scope(
    state: &ServiceState,
    scope: &ScopeProject,
) -> Result<Option<Project>, KeystoneApiError> {
    let project = if let Some(pid) = &scope.id {
        let exec = ExecutionContext::internal(state);
        state
            .provider
            .get_resource_provider()
            .get_project(&exec, pid)
            .await?
    } else if let Some(name) = &scope.name {
        if let Some(domain) = &scope.domain {
            let exec = ExecutionContext::internal(state);
            let domain_id = match &domain.id {
                Some(id) => id.clone(),
                None => {
                    state
                        .provider
                        .get_resource_provider()
                        .find_domain_by_name(
                            &exec,
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
                .get_project_by_name(&exec, name, &domain_id)
                .await?
        } else {
            return Err(KeystoneApiError::ProjectDomain);
        }
    } else {
        return Err(KeystoneApiError::ProjectIdOrName);
    };
    Ok(project)
}

/// Convert [ProviderScope] to [ScopeInfo].
///
/// # Arguments
/// * `state`: The service state
/// * `scope`: The scope to extract the scope information from
///
/// # Returns
/// * `Ok(ScopeInfo)`: The scope information
/// * `Err(KeystoneApiError)`: An error if the scope is not valid
#[tracing::instrument(name = "auth.get_authz_info", level = "debug", skip(state), err)]
pub async fn get_authz_info(
    state: &ServiceState,
    scope: Option<&ProviderScope>,
) -> Result<ScopeInfo, KeystoneApiError> {
    let authz_scope = match scope {
        Some(ProviderScope::Project(scope)) => {
            if let Some(project) = find_project_from_scope(state, &scope.into()).await? {
                let domain_id = project.domain_id.clone();
                ScopeInfo::Project {
                    project: project.into(),
                    project_domain: get_domain(state, Some(&domain_id), None::<&str>)
                        .await?
                        .into(),
                }
            } else {
                return Err(KeystoneApiError::UnauthorizedNoContext);
            }
        }
        Some(ProviderScope::Domain(scope)) => {
            if let Ok(domain) = get_domain(state, scope.id.as_ref(), scope.name.as_ref()).await {
                ScopeInfo::Domain(domain.into())
            } else {
                return Err(KeystoneApiError::UnauthorizedNoContext);
            }
        }
        Some(ProviderScope::System(_scope)) => ScopeInfo::System("system".into()),
        // TODO: Trust scope should be handled here
        Some(ProviderScope::Unscoped) => ScopeInfo::Unscoped,
        None => ScopeInfo::Unscoped,
    };
    authz_scope.validate()?;

    Ok(authz_scope)
}

#[cfg(test)]
mod tests {

    use openstack_keystone_core_types::resource::Domain;

    use super::*;
    use crate::api::tests::get_mocked_state;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

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

        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
            true,
            None,
        )
        .await;

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
