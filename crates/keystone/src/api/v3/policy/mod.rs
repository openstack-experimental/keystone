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
//! `/v3/policies` API — legacy policy document storage (issue #1035).
//!
//! CRUD over opaque, arbitrarily serialized policy documents that *remote*
//! services fetch and interpret. Deprecated upstream ("Keystone is not a
//! policy management service"), implemented for python API compatibility.
//!
//! Not to be confused with this service's own authorization, which is decided
//! by OPA over `policy/**/*.rego`.
//!
//! Routes mirror python keystone exactly: `GET`/`POST` on the collection and
//! `GET`/`PATCH`/`DELETE` on the member. There is deliberately **no `PUT`** —
//! `PolicyResource` upstream defines only those five verbs, so
//! `PUT /v3/policies/{id}` must stay a 405.

use serde_json::{Value, json};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

mod create;
mod delete;
mod list;
mod show;
pub mod types;
mod update;

/// Wrap a non-sensitive field projection in the `{"policy": …}` envelope that
/// every `policy/policy/*.rego` rule reads (ADR 0002).
///
/// # Security Note
///
/// The projection itself is built by `to_policy_input()` on the API types,
/// which *constructs* the document from an allowlist (`id`, `type`) rather
/// than filtering a denylist out of it. A policy `blob` is arbitrary
/// caller-supplied data and `extra` has an open key space, so either could
/// carry secrets; no `.rego` rule reads them, and an external OPA can persist
/// policy input via decision logging.
pub(super) fn policy_input(projection: Value) -> Value {
    json!({ "policy": projection })
}

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list, create::create))
        .routes(routes!(show::show, update::update, delete::delete))
}

/// Gate B3 (security review V3a, issue #979): the five handlers driven
/// against a real `opa run` subprocess evaluating the repository's actual
/// `policy/policy/*.rego`, instead of a mock's canned allow/deny.
///
/// The mocked tests prove each handler *builds* the documented input; only
/// these prove the input the handler actually sends is decided the way
/// python keystone's defaults decide it —
/// `RULE_ADMIN_OR_SYSTEM_READER` for `list`/`show`, `RULE_ADMIN_REQUIRED`
/// for `create`/`update`/`delete`.
#[cfg(test)]
mod real_policy_decision {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core::auth::ValidatedSecurityContext;
    use openstack_keystone_core_types::policy_store::PolicyBuilder;

    use super::openapi_router;
    use crate::api::tests::get_state_with_real_policy;
    use crate::api::tests::real_policy_fixtures::{member_vsc, system_scoped_vsc};
    use crate::policy_store::MockPolicyStoreProvider;
    use crate::provider::Provider;

    fn stored() -> openstack_keystone_core_types::policy_store::Policy {
        PolicyBuilder::default()
            .id("pid")
            .r#type("application/json")
            .blob(serde_json::Value::String("doc".into()))
            .build()
            .unwrap()
    }

    fn provider_with_everything() -> crate::provider::ProviderBuilder {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_list_policies()
            .returning(|_, _| Ok(vec![stored()]));
        mock.expect_get_policy()
            .returning(|_, _| Ok(Some(stored())));
        mock.expect_create_policy().returning(|_, _| Ok(stored()));
        mock.expect_update_policy()
            .returning(|_, _, _| Ok(stored()));
        mock.expect_delete_policy().returning(|_, _| Ok(()));
        Provider::mocked_builder().mock_policy_store(mock)
    }

    /// Drive one request through the real Rego and return its status.
    async fn status_for(
        vsc: ValidatedSecurityContext,
        method: &str,
        uri: &str,
        body: Option<&'static str>,
    ) -> StatusCode {
        let (state, _opa) = get_state_with_real_policy(provider_with_everything()).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let mut request = Request::builder().method(method).uri(uri).extension(vsc);
        if body.is_some() {
            request = request.header("content-type", "application/json");
        }
        let request = request
            .body(body.map_or_else(Body::empty, Body::from))
            .unwrap();

        api.as_service().oneshot(request).await.unwrap().status()
    }

    /// `admin` passes every verb.
    #[tokio::test]
    async fn test_real_policy_admin_allowed_everywhere() {
        let admin = || member_vsc("uid", "pid", &["admin"]);

        assert_eq!(status_for(admin(), "GET", "/", None).await, StatusCode::OK);
        assert_eq!(
            status_for(admin(), "GET", "/pid", None).await,
            StatusCode::OK
        );
        assert_eq!(
            status_for(
                admin(),
                "POST",
                "/",
                Some(r#"{"policy": {"type": "application/json", "blob": "b"}}"#)
            )
            .await,
            StatusCode::CREATED
        );
        assert_eq!(
            status_for(
                admin(),
                "PATCH",
                "/pid",
                Some(r#"{"policy": {"type": "text/plain"}}"#)
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            status_for(admin(), "DELETE", "/pid", None).await,
            StatusCode::NO_CONTENT
        );
    }

    /// A system-scoped `reader` may read (`list`, `show`) — the
    /// `RULE_ADMIN_OR_SYSTEM_READER` path, exercised through the real
    /// `input.credentials.system` projection rather than a
    /// hand-written Rego input.
    #[tokio::test]
    async fn test_real_policy_system_reader_may_read() {
        assert_eq!(
            status_for(
                system_scoped_vsc("uid", "system", &["reader"]),
                "GET",
                "/",
                None
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            status_for(
                system_scoped_vsc("uid", "system", &["reader"]),
                "GET",
                "/pid",
                None
            )
            .await,
            StatusCode::OK
        );
    }

    /// ... but must not write: `create`/`update`/`delete` are
    /// `RULE_ADMIN_REQUIRED` upstream, with no system-reader path.
    #[tokio::test]
    async fn test_real_policy_system_reader_may_not_write() {
        assert_eq!(
            status_for(
                system_scoped_vsc("uid", "system", &["reader"]),
                "POST",
                "/",
                Some(r#"{"policy": {"type": "application/json", "blob": "b"}}"#)
            )
            .await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status_for(
                system_scoped_vsc("uid", "system", &["reader"]),
                "PATCH",
                "/pid",
                Some(r#"{"policy": {"type": "text/plain"}}"#)
            )
            .await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status_for(
                system_scoped_vsc("uid", "system", &["reader"]),
                "DELETE",
                "/pid",
                None
            )
            .await,
            StatusCode::FORBIDDEN
        );
    }

    /// A project-scoped `reader` is not a *system* reader: it may not even
    /// read. Catches dropping the `system_scope` conjunct from the read
    /// rules.
    #[tokio::test]
    async fn test_real_policy_project_reader_denied() {
        assert_eq!(
            status_for(member_vsc("uid", "pid", &["reader"]), "GET", "/", None).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status_for(member_vsc("uid", "pid", &["reader"]), "GET", "/pid", None).await,
            StatusCode::FORBIDDEN
        );
    }

    /// A domain-scoped system value is not `"all"`.
    #[tokio::test]
    async fn test_real_policy_non_all_system_scope_denied() {
        assert_eq!(
            status_for(
                system_scoped_vsc("uid", "other_system", &["reader"]),
                "GET",
                "/",
                None
            )
            .await,
            StatusCode::FORBIDDEN
        );
    }

    /// Security model I8 against the real Rego: a system reader whose
    /// per-item `show` check passes sees the item; a plain `member` gets
    /// the collection check itself refused, so no item can leak.
    #[tokio::test]
    async fn test_real_policy_member_cannot_list() {
        assert_eq!(
            status_for(member_vsc("uid", "pid", &["member"]), "GET", "/", None).await,
            StatusCode::FORBIDDEN
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::{openapi_router, policy_input};
    use crate::api::tests::{get_mocked_state, policy_contract};
    use crate::api::v3::policy::types::Policy;
    use crate::provider::Provider;

    /// Gate I (security review V9, issue #987): a direct structural test on
    /// the projection itself, independent of any handler round-trip. A future
    /// field addition to the API `Policy` cannot leak into policy input,
    /// because the projection is an allowlist rather than a filter.
    #[test]
    fn test_policy_input_never_leaks_blob_or_extra() {
        let policy = Policy {
            id: "pid".into(),
            r#type: "application/json".into(),
            blob: serde_json::json!("{\"secret\": \"s3cr3t\"}"),
            extra: HashMap::from([
                ("password".into(), serde_json::json!("hunter2")),
                (
                    "deeply".into(),
                    serde_json::json!({"nested": {"totp_seed": "AAAA"}}),
                ),
            ]),
        };

        let input = policy_input(policy.to_policy_input());
        policy_contract::assert_object_keys(&input, &["policy"]);
        policy_contract::assert_no_secrets(&input);

        let rendered = input.to_string();
        for needle in ["s3cr3t", "hunter2", "AAAA"] {
            assert!(
                !rendered.contains(needle),
                "policy input must not contain {needle}: {rendered}"
            );
        }
    }

    /// The envelope key must be exactly `policy`: a mis-keyed resource makes
    /// every `input.target.policy.*` lookup `undefined` in Rego, which an
    /// `undefined`-driven rule can silently treat as allow.
    #[test]
    fn test_policy_input_envelope_key() {
        let input = policy_input(serde_json::json!({"id": "x", "type": "t"}));
        policy_contract::assert_object_keys(&input, &["policy"]);
        assert_eq!(input["policy"]["id"], "x");
    }

    /// Python keystone's `PolicyResource` exposes only `GET`/`POST` on the
    /// collection and `GET`/`PATCH`/`DELETE` on the member. `PUT
    /// /v3/policies/{id}` must therefore be a 405, not a create-or-update
    /// (unlike `PUT /v3/regions/{id}`, which python keystone *does* define).
    #[tokio::test]
    async fn test_put_member_is_method_not_allowed() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router().with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/pid")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"policy": {"type": "t", "blob": "b"}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// The generated OpenAPI document must publish exactly the five upstream
    /// operations and no `put`.
    #[test]
    fn test_openapi_publishes_five_operations_and_no_put() {
        let (_, api) = openapi_router().split_for_parts();

        let collection = api.paths.paths.get("/").expect("collection path published");
        assert!(collection.get.is_some(), "GET /v3/policies");
        assert!(collection.post.is_some(), "POST /v3/policies");
        assert!(collection.put.is_none(), "no PUT on the collection");
        assert!(collection.patch.is_none(), "no PATCH on the collection");
        assert!(collection.delete.is_none(), "no DELETE on the collection");

        let member = api
            .paths
            .paths
            .get("/{policy_id}")
            .expect("member path published");
        assert!(member.get.is_some(), "GET /v3/policies/{{policy_id}}");
        assert!(member.patch.is_some(), "PATCH /v3/policies/{{policy_id}}");
        assert!(member.delete.is_some(), "DELETE /v3/policies/{{policy_id}}");
        assert!(
            member.put.is_none(),
            "PUT /v3/policies/{{policy_id}} does not exist upstream"
        );
        assert!(member.post.is_none(), "no POST on the member");

        assert_eq!(
            api.paths.paths.len(),
            2,
            "only the collection and member paths are published"
        );
    }
}
