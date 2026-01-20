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
use serde::Serialize;
use url::Url;

use crate::api::KeystoneApiError;
use crate::api::types::{Link, ScopeProject};
use crate::config::Config;
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
    scope: &ScopeProject,
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

/// Prepare the links for the paginated resource collection.
pub fn build_pagination_links<T, Q>(
    config: &Config,
    data: &[T],
    query: &Q,
    collection_url: &str,
) -> Result<Option<Vec<Link>>, KeystoneApiError>
where
    T: ResourceIdentifier,
    Q: QueryParameterPagination + Clone + Serialize,
{
    Ok(match &query.get_limit() {
        Some(limit) => {
            if (data.len() as u64) >= *limit
                && let Some(last_id) = data.last().map(|x| x.get_id())
            {
                let mut url = if let Some(pe) = &config.default.public_endpoint {
                    pe.clone()
                } else {
                    Url::parse("http://localhost")?
                };
                url.set_path(collection_url);
                let mut new_query = query.clone();

                new_query.set_marker(last_id);
                url.set_query(Some(&serde_urlencoded::to_string(&new_query)?));

                let next_page_url = format!(
                    "{}{}",
                    url.path(),
                    url.query().map(|q| format!("?{}", q)).unwrap_or_default()
                );
                Some(vec![Link {
                    rel: String::from("next"),
                    href: next_page_url,
                }])
            } else {
                None
            }
        }
        None => None,
    })
}

/// Resource query parameters pagination extension trait.
pub trait QueryParameterPagination {
    /// Get the page limit.
    fn get_limit(&self) -> Option<u64>;
    /// Set the pagination marker.
    fn set_marker(&mut self, marker: String) -> &mut Self;
}

/// Trait for the resource to expose the unique identifier that can be used for
/// building the marker pagination.
pub trait ResourceIdentifier {
    /// Get the unique resource identifier.
    fn get_id(&self) -> String;
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
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

    /// Fake resource for pagination testing
    struct FakeResource {
        pub id: String,
    }

    /// Fake query params for pagination testing
    #[derive(Clone, Default, Serialize)]
    struct FakeQueryParams {
        pub marker: Option<String>,
        pub limit: Option<u64>,
    }

    impl ResourceIdentifier for FakeResource {
        fn get_id(&self) -> String {
            self.id.clone()
        }
    }

    impl QueryParameterPagination for FakeQueryParams {
        fn get_limit(&self) -> Option<u64> {
            self.limit
        }

        fn set_marker(&mut self, marker: String) -> &mut Self {
            self.marker = Some(marker);
            self
        }
    }

    /// Parameterized pagination test
    #[rstest]
    #[case(5, FakeQueryParams::default(), None)]
    #[case(5, FakeQueryParams{marker: Some("x".into()), limit: None}, None)]
    #[case(5, FakeQueryParams{marker: Some("x".into()), limit: Some(6)}, None)]
    #[case(5, FakeQueryParams{marker: Some("x".into()), limit: Some(5)}, Some(vec![
        Link {
            rel: "next".into(),
            href: "/foo/bar?marker=4&limit=5".into()
        }])
    )]
    #[case(5, FakeQueryParams{marker: Some("x".into()), limit: Some(3)}, Some(vec![
        Link {
            rel: "next".into(),
            href: "/foo/bar?marker=4&limit=3".into()
        }])
    )]
    #[case(5, FakeQueryParams{marker: Some("x".into()), limit: Some(1)}, Some(vec![
        Link {
            rel: "next".into(),
            href: "/foo/bar?marker=4&limit=1".into()
        }])
    )]
    #[case(5, FakeQueryParams{marker: Some("x".into()), limit: Some(0)}, Some(vec![
        Link {
            rel: "next".into(),
            href: "/foo/bar?marker=4&limit=0".into()
        }])
    )]
    #[case(0, FakeQueryParams{marker: Some("x".into()), limit: Some(6)}, None)]
    #[case(0, FakeQueryParams{marker: None, limit: Some(6)}, None)]
    #[case(5, FakeQueryParams{marker: None, limit: Some(5)}, Some(vec![
        Link {
            rel: "next".into(),
            href: "/foo/bar?marker=4&limit=5".into()
        }])
    )]
    fn test_pagination(
        #[case] cnt: usize,
        #[case] query: FakeQueryParams,
        #[case] expected: Option<Vec<Link>>,
    ) {
        assert_eq!(
            build_pagination_links(
                &Config::default(),
                Vec::from_iter((0..cnt).map(|x| FakeResource { id: x.to_string() })).as_slice(),
                &query,
                "foo/bar",
            )
            .unwrap(),
            expected
        );
    }
}
