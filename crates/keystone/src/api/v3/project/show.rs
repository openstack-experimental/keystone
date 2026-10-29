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
//! # Show project API

use std::collections::{BTreeMap, HashMap, HashSet};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::{Value, json};

use openstack_keystone_core_types::resource::Project as ProviderProject;

use super::types::{
    Project, ProjectHierarchy, ProjectHierarchyItem, ProjectHierarchyResponse,
    ProjectShowParameters, ProjectWithHierarchy,
};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::policy::PolicyError;
use openstack_keystone_core::auth::{ExecutionContext, ValidatedSecurityContext};

/// Whether the boolean query flag is set: present with the empty value or any
/// value other than `false` or `0`.
fn flag(value: &Option<String>) -> bool {
    value
        .as_deref()
        .is_some_and(|x| !matches!(x.to_ascii_lowercase().as_str(), "false" | "0"))
}

/// Keep only the projects the caller is allowed to see.
///
/// Every project is checked individually with the `show` policy.
async fn filter_visible(
    state: &ServiceState,
    user_auth: &ValidatedSecurityContext,
    projects: Vec<ProviderProject>,
) -> Result<Vec<ProviderProject>, KeystoneApiError> {
    let mut res = Vec::with_capacity(projects.len());
    for project in projects {
        match state
            .policy_enforcer
            .enforce(
                "identity/resource/project/show",
                user_auth,
                Value::Null,
                Some(json!({"project": &project})),
            )
            .await
        {
            Ok(_) => res.push(project),
            Err(PolicyError::Forbidden(_)) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(res)
}

fn to_list(projects: Vec<ProviderProject>) -> ProjectHierarchy {
    ProjectHierarchy::List(
        projects
            .into_iter()
            .map(|x| ProjectHierarchyItem {
                project: Project::from(x),
            })
            .collect(),
    )
}

/// Nested `{id: {id: null}}` object for the chain of parents (closest first).
fn parents_to_ids(projects: &[ProviderProject]) -> ProjectHierarchy {
    let mut nested = Value::Null;
    for project in projects.iter().rev() {
        nested = json!({ project.id.as_str(): nested });
    }
    ProjectHierarchy::Ids(if nested.is_null() { json!({}) } else { nested })
}

/// Nested `{id: {id: null}}` object for the descendants.
///
/// Projects not visible to the caller are skipped and their visible
/// descendants are attached to the closest visible ancestor.
fn subtree_to_ids(
    root: &str,
    all: &[ProviderProject],
    visible: &[ProviderProject],
) -> ProjectHierarchy {
    let parent: HashMap<&str, &str> = all
        .iter()
        .filter_map(|x| x.parent_id.as_deref().map(|p| (x.id.as_str(), p)))
        .collect();
    let visible_ids: HashSet<&str> = visible.iter().map(|x| x.id.as_str()).collect();
    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    for project in visible {
        let mut anchor = parent.get(project.id.as_str()).copied();
        // Bounded by the number of projects: protects against parent loops.
        let mut hops = 0usize;
        while let Some(candidate) = anchor {
            if candidate == root || visible_ids.contains(candidate) || hops > all.len() {
                break;
            }
            anchor = parent.get(candidate).copied();
            hops += 1;
        }
        children
            .entry(anchor.unwrap_or(root))
            .or_default()
            .push(project.id.as_str());
    }
    fn build(id: &str, children: &HashMap<&str, Vec<&str>>, seen: &mut HashSet<String>) -> Value {
        let mut map: BTreeMap<String, Value> = BTreeMap::new();
        for child in children.get(id).into_iter().flatten() {
            if seen.insert((*child).to_string()) {
                map.insert((*child).to_string(), build(child, children, seen));
            }
        }
        if map.is_empty() {
            Value::Null
        } else {
            json!(map)
        }
    }
    let mut seen = HashSet::from([root.to_string()]);
    let nested = build(root, &children, &mut seen);
    ProjectHierarchy::Ids(if nested.is_null() { json!({}) } else { nested })
}

/// Get single project
///
/// The optional `parents_as_list`, `parents_as_ids`, `subtree_as_list` and
/// `subtree_as_ids` query parameters add the project hierarchy data into the
/// response. Only the projects the caller is allowed to see are returned.
#[utoipa::path(
    get,
    path = "/{project_id}",
    params(ProjectShowParameters),
    responses(
        (status = OK, description = "Single project", body = ProjectHierarchyResponse),
        (status = 400, description = "Conflicting hierarchy parameters", example = json!(KeystoneApiError::BadRequest(String::from("parents_as_list and parents_as_ids are mutually exclusive")))),
        (status = 404, description = "Project not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="projects"
)]
#[tracing::instrument(name = "api::v3::project_show", level = "debug", skip(state))]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(project_id): Path<String>,
    Query(query): Query<ProjectShowParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    if flag(&query.parents_as_list) && flag(&query.parents_as_ids) {
        return Err(KeystoneApiError::BadRequest(
            "parents_as_list and parents_as_ids are mutually exclusive".into(),
        ));
    }
    if flag(&query.subtree_as_list) && flag(&query.subtree_as_ids) {
        return Err(KeystoneApiError::BadRequest(
            "subtree_as_list and subtree_as_ids are mutually exclusive".into(),
        ));
    }
    let ctx = ExecutionContext::from_auth(&state, &user_auth);
    let current = state
        .provider
        .get_resource_provider()
        .get_project(&ctx, &project_id)
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/resource/project/show",
            &user_auth,
            serde_json::Value::Null,
            Some(json!({"project": current})),
        )
        .await?;
    let Some(current) = current else {
        return Err(KeystoneApiError::NotFound {
            resource: "project".to_string(),
            identifier: project_id.clone(),
        });
    };

    let mut parents = None;
    if flag(&query.parents_as_list) || flag(&query.parents_as_ids) {
        let found = state
            .provider
            .get_resource_provider()
            .get_project_parents(&ctx, &project_id)
            .await?
            .unwrap_or_default();
        let visible = filter_visible(&state, &user_auth, found).await?;
        parents = Some(if flag(&query.parents_as_list) {
            to_list(visible)
        } else {
            parents_to_ids(&visible)
        });
    }
    let mut subtree = None;
    if flag(&query.subtree_as_list) || flag(&query.subtree_as_ids) {
        let found = state
            .provider
            .get_resource_provider()
            .get_project_subtree(&ctx, &project_id)
            .await?
            .unwrap_or_default();
        let visible = filter_visible(&state, &user_auth, found.clone()).await?;
        subtree = Some(if flag(&query.subtree_as_list) {
            to_list(visible)
        } else {
            subtree_to_ids(&project_id, &found, &visible)
        });
    }

    Ok((
        StatusCode::OK,
        Json(ProjectHierarchyResponse {
            project: ProjectWithHierarchy {
                project: Project::from(current),
                parents,
                subtree,
            },
        }),
    ))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::resource::Project as ProviderProject;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::project::types::{
        Project as ApiProject, ProjectResponse as ApiProjectResponse,
    };
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    #[tokio::test]
    async fn test_get() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(ProviderProject {
                    id: "bar".into(),
                    domain_id: "did".into(),
                    enabled: true,
                    name: "project_name".into(),
                    ..Default::default()
                }))
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo")
                    .extension(vsc.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/bar")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApiProjectResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiProject {
                tags: Default::default(),
                description: None,
                domain_id: "did".into(),
                enabled: true,
                extra: std::collections::HashMap::new(),
                id: "bar".into(),
                links: Some(openstack_keystone_api_types::ResourceLinks::new(
                    "/v3/projects/bar".into()
                )),
                is_domain: false,
                name: "project_name".into(),
                parent_id: None,
                options: Default::default(),
            },
            res.project,
        );
    }

    #[tokio::test]
    async fn test_get_not_allowed() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(ProviderProject {
                    id: "foo".into(),
                    domain_id: "did".into(),
                    enabled: true,
                    name: "project_name".into(),
                    ..Default::default()
                }))
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
            false,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    fn proj(id: &str, parent: Option<&str>) -> ProviderProject {
        ProviderProject {
            id: id.into(),
            domain_id: "did".into(),
            enabled: true,
            name: format!("{id}_name"),
            parent_id: parent.map(Into::into),
            ..Default::default()
        }
    }

    fn hierarchy_mock() -> MockResourceProvider {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "p2")
            .returning(|_, _| Ok(Some(proj("p2", Some("p1")))));
        resource_mock
            .expect_get_project_parents()
            .withf(|_, id: &'_ str| id == "p2")
            .returning(|_, _| Ok(Some(vec![proj("p1", Some("did")), proj("did", None)])));
        resource_mock
            .expect_get_project_subtree()
            .withf(|_, id: &'_ str| id == "p2")
            .returning(|_, _| {
                Ok(Some(vec![
                    proj("p3", Some("p2")),
                    proj("p4", Some("p2")),
                    proj("p5", Some("p3")),
                ]))
            });
        resource_mock
    }

    async fn get_json(
        uri: &str,
        resource_mock: MockResourceProvider,
        allow: bool,
    ) -> (StatusCode, serde_json::Value) {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
            allow,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    #[tokio::test]
    async fn test_get_parents_as_list() {
        let (status, body) = get_json("/p2?parents_as_list", hierarchy_mock(), true).await;
        assert_eq!(status, StatusCode::OK);
        let parents = body["project"]["parents"].as_array().unwrap();
        assert_eq!(parents.len(), 2);
        assert_eq!(parents[0]["project"]["id"], "p1");
        assert_eq!(parents[1]["project"]["id"], "did");
        assert!(body["project"].get("subtree").is_none());
    }

    #[tokio::test]
    async fn test_get_parents_as_ids() {
        let (status, body) = get_json("/p2?parents_as_ids=true", hierarchy_mock(), true).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["project"]["parents"], json!({"p1": {"did": null}}));
    }

    #[tokio::test]
    async fn test_get_subtree_as_list() {
        let (status, body) = get_json("/p2?subtree_as_list", hierarchy_mock(), true).await;
        assert_eq!(status, StatusCode::OK);
        let ids: Vec<&str> = body["project"]["subtree"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["project"]["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["p3", "p4", "p5"]);
    }

    #[tokio::test]
    async fn test_get_subtree_as_ids() {
        let (status, body) = get_json("/p2?subtree_as_ids", hierarchy_mock(), true).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["project"]["subtree"],
            json!({"p3": {"p5": null}, "p4": null})
        );
    }

    #[tokio::test]
    async fn test_get_hierarchy_flag_false_is_ignored() {
        let (status, body) = get_json("/p2?parents_as_list=false", hierarchy_mock(), true).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["project"].get("parents").is_none());
    }

    #[tokio::test]
    async fn test_get_hierarchy_conflicting_params() {
        let (status, _) =
            get_json("/p2?parents_as_list&parents_as_ids", hierarchy_mock(), true).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) =
            get_json("/p2?subtree_as_list&subtree_as_ids", hierarchy_mock(), true).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_hierarchy_not_allowed() {
        let (status, _) = get_json("/p2?parents_as_list", hierarchy_mock(), false).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_hierarchy_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/p2?parents_as_list")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_get_hierarchy_policy_input() {
        use crate::api::tests::{get_capturing_state, policy_contract};

        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_resource(hierarchy_mock())).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/p2?parents_as_list&subtree_as_list")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());

        // One check for the project itself, then one per relative.
        let calls = policy.calls();
        assert_eq!(calls.len(), 1 + 2 + 3);
        for call in &calls {
            assert_eq!(call.policy_name, "identity/resource/project/show");
            assert_eq!(call.target, serde_json::Value::Null);
            policy_contract::assert_existing_presence(&call.existing, true);
            let existing = call.existing.as_ref().unwrap();
            policy_contract::assert_object_keys(existing, &["project"]);
            policy_contract::assert_no_secrets(existing);
        }
    }

    fn ids(h: super::ProjectHierarchy) -> serde_json::Value {
        match h {
            super::ProjectHierarchy::Ids(v) => v,
            super::ProjectHierarchy::List(_) => panic!("ids expected"),
        }
    }

    #[test]
    fn test_subtree_to_ids_all_visible() {
        let all = vec![
            proj("p3", Some("p2")),
            proj("p4", Some("p2")),
            proj("p5", Some("p3")),
        ];
        assert_eq!(
            ids(super::subtree_to_ids("p2", &all, &all)),
            json!({"p3": {"p5": null}, "p4": null})
        );
    }

    #[test]
    fn test_subtree_to_ids_reanchors_hidden_middle() {
        // p3 is not visible: its visible child p5 is attached to the root.
        let all = vec![
            proj("p3", Some("p2")),
            proj("p4", Some("p2")),
            proj("p5", Some("p3")),
        ];
        let visible = vec![proj("p4", Some("p2")), proj("p5", Some("p3"))];
        assert_eq!(
            ids(super::subtree_to_ids("p2", &all, &visible)),
            json!({"p4": null, "p5": null})
        );
    }

    #[test]
    fn test_subtree_to_ids_reanchors_to_closest_visible_ancestor() {
        // p3 (visible) -> p5 (hidden) -> p6 (visible): p6 hangs under p3.
        let all = vec![
            proj("p3", Some("p2")),
            proj("p5", Some("p3")),
            proj("p6", Some("p5")),
        ];
        let visible = vec![proj("p3", Some("p2")), proj("p6", Some("p5"))];
        assert_eq!(
            ids(super::subtree_to_ids("p2", &all, &visible)),
            json!({"p3": {"p6": null}})
        );
    }

    #[test]
    fn test_subtree_to_ids_empty() {
        assert_eq!(ids(super::subtree_to_ids("p2", &[], &[])), json!({}));
    }

    #[test]
    fn test_subtree_to_ids_parent_loop_terminates() {
        let all = vec![proj("p3", Some("p4")), proj("p4", Some("p3"))];
        // Must not hang or overflow the stack; content is unspecified.
        let _ = super::subtree_to_ids("p2", &all, &all);
    }

    #[test]
    fn test_parents_to_ids() {
        let parents = vec![proj("p1", Some("did")), proj("did", None)];
        assert_eq!(
            ids(super::parents_to_ids(&parents)),
            json!({"p1": {"did": null}})
        );
        assert_eq!(ids(super::parents_to_ids(&[])), json!({}));
    }
}
