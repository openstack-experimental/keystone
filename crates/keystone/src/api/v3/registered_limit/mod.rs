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
//! # Registered limits API
//!
//! `/v3/registered_limits` -- the service wide defaults of the resource limits
//! (Python Keystone "Unified Limits").

use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

mod create;
mod delete;
mod list;
mod show;
pub mod types;
mod update;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list, create::create))
        .routes(routes!(show::show, update::update, delete::delete))
}

/// Gate B3: the handlers driven against a real `opa run` subprocess
/// evaluating the repository's actual `policy/registered_limit/*.rego`.
#[cfg(test)]
mod real_policy_decision {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core::auth::ValidatedSecurityContext;
    use openstack_keystone_core_types::limit as provider_types;

    use super::openapi_router;
    use crate::api::tests::get_state_with_real_policy;
    use crate::api::tests::real_policy_fixtures::{member_vsc, system_scoped_vsc};
    use crate::limit::MockLimitProvider;
    use crate::provider::Provider;

    fn stored() -> provider_types::RegisteredLimit {
        provider_types::RegisteredLimit {
            default_limit: 10,
            description: None,
            id: "r1".into(),
            region_id: None,
            resource_name: "cores".into(),
            service_id: "srv".into(),
        }
    }

    fn provider() -> crate::provider::ProviderBuilder {
        let mut mock = MockLimitProvider::default();
        mock.expect_list_registered_limits()
            .returning(|_, _| Ok(vec![stored()]));
        mock.expect_get_registered_limit()
            .returning(|_, _| Ok(Some(stored())));
        mock.expect_create_registered_limits()
            .returning(|_, _| Ok(vec![stored()]));
        mock.expect_update_registered_limit()
            .returning(|_, _, _| Ok(stored()));
        mock.expect_delete_registered_limit()
            .returning(|_, _| Ok(()));
        Provider::mocked_builder().mock_limit(mock)
    }

    async fn status(
        vsc: ValidatedSecurityContext,
        method: &str,
        uri: &str,
        body: Option<&'static str>,
    ) -> StatusCode {
        let (state, _opa) = get_state_with_real_policy(provider()).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let mut request = Request::builder().method(method).uri(uri).extension(vsc);
        if body.is_some() {
            request = request.header("content-type", "application/json");
        }
        api.as_service()
            .oneshot(
                request
                    .body(body.map_or_else(Body::empty, Body::from))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    const CREATE: &str = r#"{"registered_limits": [{"service_id": "srv", "resource_name": "cores", "default_limit": 1}]}"#;
    const UPDATE: &str = r#"{"registered_limit": {"default_limit": 2}}"#;

    #[tokio::test]
    async fn test_real_policy_admin_allowed_everywhere() {
        let admin = || member_vsc("uid", "p1", &["admin"]);
        assert_eq!(StatusCode::OK, status(admin(), "GET", "/", None).await);
        assert_eq!(StatusCode::OK, status(admin(), "GET", "/r1", None).await);
        assert_eq!(
            StatusCode::CREATED,
            status(admin(), "POST", "/", Some(CREATE)).await
        );
        assert_eq!(
            StatusCode::OK,
            status(admin(), "PATCH", "/r1", Some(UPDATE)).await
        );
        assert_eq!(
            StatusCode::NO_CONTENT,
            status(admin(), "DELETE", "/r1", None).await
        );
    }

    /// Any scoped caller may read, only the admin may write.
    #[tokio::test]
    async fn test_real_policy_member_reads_but_does_not_write() {
        let member = || member_vsc("uid", "p1", &["member"]);
        assert_eq!(StatusCode::OK, status(member(), "GET", "/", None).await);
        assert_eq!(StatusCode::OK, status(member(), "GET", "/r1", None).await);
        assert_eq!(
            StatusCode::FORBIDDEN,
            status(member(), "POST", "/", Some(CREATE)).await
        );
        assert_eq!(
            StatusCode::FORBIDDEN,
            status(member(), "PATCH", "/r1", Some(UPDATE)).await
        );
        assert_eq!(
            StatusCode::FORBIDDEN,
            status(member(), "DELETE", "/r1", None).await
        );
    }

    #[tokio::test]
    async fn test_real_policy_system_reader_may_not_write() {
        let reader = || system_scoped_vsc("uid", "system", &["reader"]);
        assert_eq!(StatusCode::OK, status(reader(), "GET", "/", None).await);
        assert_eq!(
            StatusCode::FORBIDDEN,
            status(reader(), "POST", "/", Some(CREATE)).await
        );
        assert_eq!(
            StatusCode::FORBIDDEN,
            status(reader(), "DELETE", "/r1", None).await
        );
    }
}
