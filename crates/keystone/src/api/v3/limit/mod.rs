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
//! # Limits API
//!
//! `/v3/limits` -- the resource limits of the projects and domains (Python
//! Keystone "Unified Limits") and `/v3/limits/model` -- the enforcement model
//! discovery.

use serde_json::{Value, json};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

mod create;
mod delete;
mod list;
mod model;
mod show;
pub mod types;
mod update;

/// Wrap the limit into the `{"limit": ...}` envelope read by the
/// `policy/limit/*.rego` rules.
///
/// The domain of the project the limit is set for is added as the
/// `project_domain_id` attribute: the domain scoped callers are allowed to
/// read the limits of the projects in their domain (Python Keystone resolves
/// it the same way through `target.limit.project.domain_id`).
pub(super) async fn limit_policy_view(
    state: &ServiceState,
    exec: &ExecutionContext<'_>,
    limit: &types::Limit,
) -> Result<Value, KeystoneApiError> {
    let mut view = json!(limit);
    let project_domain_id = match &limit.project_id {
        Some(project_id) => state
            .provider
            .get_resource_provider()
            .get_project(exec, project_id)
            .await?
            .map(|project| project.domain_id),
        None => None,
    };
    view["project_domain_id"] = json!(project_domain_id);
    Ok(json!({"limit": view}))
}

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    // The static `/model` segment takes precedence over `/{limit_id}`.
    OpenApiRouter::new()
        .routes(routes!(list::list, create::create))
        .routes(routes!(model::model))
        .routes(routes!(show::show, update::update, delete::delete))
}

/// Gate B3: the handlers driven against a real `opa run` subprocess
/// evaluating the repository's actual `policy/limit/*.rego`.
#[cfg(test)]
mod real_policy_decision {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core::auth::ValidatedSecurityContext;
    use openstack_keystone_core_types::limit as provider_types;
    use openstack_keystone_core_types::resource::Project;

    use super::openapi_router;
    use super::types::LimitList;
    use crate::api::tests::get_state_with_real_policy;
    use crate::api::tests::real_policy_fixtures::{
        member_vsc, restricted_app_cred_vsc, system_scoped_vsc,
    };
    use crate::limit::MockLimitProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    fn stored(id: &str, project_id: &str) -> provider_types::Limit {
        provider_types::Limit {
            description: None,
            domain_id: None,
            id: id.into(),
            project_id: Some(project_id.into()),
            region_id: None,
            resource_limit: 10,
            resource_name: "cores".into(),
            service_id: "srv".into(),
        }
    }

    fn provider() -> crate::provider::ProviderBuilder {
        let mut mock = MockLimitProvider::default();
        mock.expect_list_limits()
            .returning(|_, _| Ok(vec![stored("l1", "p1"), stored("l2", "p2")]));
        mock.expect_get_limit().returning(|_, id| {
            Ok(Some(match id {
                "l1" => stored("l1", "p1"),
                _ => stored("l2", "p2"),
            }))
        });
        mock.expect_create_limits()
            .returning(|_, _| Ok(vec![stored("l1", "p1")]));
        mock.expect_update_limit()
            .returning(|_, _, _| Ok(stored("l1", "p1")));
        mock.expect_delete_limit().returning(|_, _| Ok(()));
        mock.expect_get_limit_model().returning(|_| {
            Ok(provider_types::LimitModel {
                name: "flat".into(),
                description: "d".into(),
            })
        });
        let mut resource = MockResourceProvider::default();
        resource.expect_get_project().returning(|_, id| {
            Ok(Some(Project {
                id: id.into(),
                domain_id: "d1".into(),
                ..Default::default()
            }))
        });
        Provider::mocked_builder()
            .mock_limit(mock)
            .mock_resource(resource)
    }

    async fn call(
        vsc: ValidatedSecurityContext,
        method: &str,
        uri: &str,
        body: Option<&'static str>,
    ) -> (StatusCode, Vec<u8>) {
        let (state, _opa) = get_state_with_real_policy(provider()).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let mut request = Request::builder().method(method).uri(uri).extension(vsc);
        if body.is_some() {
            request = request.header("content-type", "application/json");
        }
        let response = api
            .as_service()
            .oneshot(
                request
                    .body(body.map_or_else(Body::empty, Body::from))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        (
            status,
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    }

    async fn status(
        vsc: ValidatedSecurityContext,
        method: &str,
        uri: &str,
        body: Option<&'static str>,
    ) -> StatusCode {
        call(vsc, method, uri, body).await.0
    }

    const CREATE: &str = r#"{"limits": [{"service_id": "srv", "resource_name": "cores", "resource_limit": 1, "project_id": "p1"}]}"#;
    const UPDATE: &str = r#"{"limit": {"resource_limit": 2}}"#;

    #[tokio::test]
    async fn test_real_policy_admin_allowed_everywhere() {
        let admin = || member_vsc("uid", "p1", &["admin"]);
        let (code, body) = call(admin(), "GET", "/", None).await;
        assert_eq!(StatusCode::OK, code);
        let res: LimitList = serde_json::from_slice(&body).unwrap();
        assert_eq!(2, res.limits.len());
        assert_eq!(StatusCode::OK, status(admin(), "GET", "/l2", None).await);
        assert_eq!(StatusCode::OK, status(admin(), "GET", "/model", None).await);
        assert_eq!(
            StatusCode::CREATED,
            status(admin(), "POST", "/", Some(CREATE)).await
        );
        assert_eq!(
            StatusCode::OK,
            status(admin(), "PATCH", "/l1", Some(UPDATE)).await
        );
        assert_eq!(
            StatusCode::NO_CONTENT,
            status(admin(), "DELETE", "/l1", None).await
        );
    }

    /// A project scoped member sees only the limits of its own project.
    #[tokio::test]
    async fn test_real_policy_project_member_sees_own_limits_only() {
        let member = || member_vsc("uid", "p1", &["member"]);
        let (code, body) = call(member(), "GET", "/", None).await;
        assert_eq!(StatusCode::OK, code);
        let res: LimitList = serde_json::from_slice(&body).unwrap();
        assert_eq!(1, res.limits.len());
        assert_eq!("l1", res.limits[0].id);

        assert_eq!(StatusCode::OK, status(member(), "GET", "/l1", None).await);
        assert_eq!(
            StatusCode::FORBIDDEN,
            status(member(), "GET", "/l2", None).await
        );
        // The enforcement model is readable by any scoped caller.
        assert_eq!(
            StatusCode::OK,
            status(member(), "GET", "/model", None).await
        );
    }

    #[tokio::test]
    async fn test_real_policy_project_member_may_not_write() {
        let member = || member_vsc("uid", "p1", &["member"]);
        assert_eq!(
            StatusCode::FORBIDDEN,
            status(member(), "POST", "/", Some(CREATE)).await
        );
        assert_eq!(
            StatusCode::FORBIDDEN,
            status(member(), "PATCH", "/l1", Some(UPDATE)).await
        );
        assert_eq!(
            StatusCode::FORBIDDEN,
            status(member(), "DELETE", "/l1", None).await
        );
    }

    #[tokio::test]
    async fn test_real_policy_system_reader() {
        let reader = || system_scoped_vsc("uid", "system", &["reader"]);
        let (code, body) = call(reader(), "GET", "/", None).await;
        assert_eq!(StatusCode::OK, code);
        let res: LimitList = serde_json::from_slice(&body).unwrap();
        assert_eq!(2, res.limits.len());
        assert_eq!(StatusCode::OK, status(reader(), "GET", "/l2", None).await);
        assert_eq!(
            StatusCode::FORBIDDEN,
            status(reader(), "POST", "/", Some(CREATE)).await
        );
        assert_eq!(
            StatusCode::FORBIDDEN,
            status(reader(), "DELETE", "/l1", None).await
        );
    }

    /// A delegated caller is bound to the project of the delegation.
    #[tokio::test]
    async fn test_real_policy_delegated_caller_is_bound_to_its_project() {
        let delegated = || restricted_app_cred_vsc("uid", "p1");
        assert_eq!(
            StatusCode::OK,
            status(delegated(), "GET", "/l1", None).await
        );
        assert_eq!(
            StatusCode::FORBIDDEN,
            status(delegated(), "GET", "/l2", None).await
        );
        let (code, body) = call(delegated(), "GET", "/", None).await;
        assert_eq!(StatusCode::OK, code);
        let res: LimitList = serde_json::from_slice(&body).unwrap();
        assert_eq!(1, res.limits.len());
    }

    #[tokio::test]
    async fn test_real_policy_unscoped_reader_denied() {
        // A system scope value other than "all" does not grant anything.
        let vsc = system_scoped_vsc("uid", "other", &["reader"]);
        assert_eq!(StatusCode::FORBIDDEN, status(vsc, "GET", "/l1", None).await);
    }
}
