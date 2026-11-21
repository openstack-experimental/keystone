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
//! # v4 project API
//!
//! Project hierarchy endpoints that python keystone does not have, therefore
//! exposed in v4 only.

use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

mod parents;
mod subtree;

/// OpenApi specification for the v4 project API.
#[derive(OpenApi)]
#[openapi()]
pub struct ApiDoc;

pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(parents::parents))
        .routes(routes!(subtree::subtree))
}

#[cfg(test)]
pub(super) mod test_support {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::resource::Project as ProviderProject;

    use super::openapi_router;
    use crate::api::tests::{get_state_with_mock_policy, test_fixture_scoped};
    use crate::policy::{MockPolicy, PolicyError, PolicyEvaluationResult};
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    pub(super) fn proj(id: &str, parent: Option<&str>) -> ProviderProject {
        ProviderProject {
            id: id.into(),
            domain_id: "did".into(),
            enabled: true,
            name: format!("{id}_name"),
            parent_id: parent.map(Into::into),
            ..Default::default()
        }
    }

    /// Issue a request against the project router.
    ///
    /// The `show` policy denies everything when `allow` is false and
    /// otherwise only the project with the `hidden` ID.
    pub(super) async fn call(
        uri: &str,
        mock: MockResourceProvider,
        allow: bool,
        hidden: Option<&'static str>,
        authed: bool,
    ) -> (StatusCode, Value) {
        let mut policy = MockPolicy::default();
        policy
            .expect_enforce()
            .returning(move |policy_name, _, _, existing| {
                let denied = !allow
                    || (policy_name == "identity/resource/project/show"
                        && hidden.is_some()
                        && existing
                            .as_ref()
                            .and_then(|value| value.pointer("/project/id"))
                            .and_then(Value::as_str)
                            == hidden);
                if denied {
                    Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()))
                } else {
                    Ok(PolicyEvaluationResult::allowed_admin())
                }
            });
        let state =
            get_state_with_mock_policy(Provider::mocked_builder().mock_resource(mock), policy)
                .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let mut req = Request::builder().uri(uri);
        if authed {
            req = req.extension(test_fixture_scoped());
        }
        let response = api
            .as_service()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }
}
