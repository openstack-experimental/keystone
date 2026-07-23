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
//! `crud_endpoint!`: boilerplate reduction for `RestEndpoint` CRUD helpers
//! (issue #992 deliverable 3).
//!
//! The macro is **crate-private** support tooling for `test_api`'s own
//! `src/` helper modules — integration tests consume the generated public
//! wrapper functions, never the macro itself.
//!
//! Every operation block is independent and fully explicit: request struct
//! names, wrapper function names and all endpoint parameters are spelled
//! out at the call site (no identifier concatenation), so compile errors
//! point at readable names. Operations are selectable — a resource without
//! an update handler simply omits the `update` block. Endpoints that do not
//! fit these shapes (sub-resources, grants, borrowed fields, non-JSON
//! bodies) should keep hand-written `RestEndpoint` impls.
//!
//! Canonical field order per operation (all fields required, see arms
//! below):
//!
//! ```text
//! crud_endpoint! {
//!     create {
//!         request = GroupCreateApiRequest,
//!         func = create_group,
//!         path = "groups",
//!         body_key = "group",
//!         create_type = GroupCreate,
//!         model = Group,
//!         response_key = "group",
//!         service = Identity,
//!         api_version = (3, 0),
//!     }
//!     show {
//!         request = GroupShowApiRequest,
//!         func = get_group,
//!         path = "groups",
//!         model = Group,
//!         response_key = "group",
//!         service = Identity,
//!         api_version = (3, 0),
//!     }
//!     list {
//!         request = GroupListRequest,
//!         func = list_groups,
//!         path = "groups",
//!         model = Group,
//!         response_key = "groups",
//!         service = Identity,
//!         api_version = (3, 0),
//!         query = [domain_id, name],
//!     }
//!     delete {
//!         request = GroupDeleteApiRequest,
//!         func = delete_group,
//!         path = "groups",
//!         model = Group,
//!         service = Identity,
//!         api_version = (3, 0),
//!     }
//! }
//! ```
//!
//! Generated per operation:
//!
//! - `create`: private request struct, `RestEndpoint` impl (POST `path`, JSON
//!   body under `body_key`), and `pub async fn <func>(tc, <create_type>) ->
//!   Result<AsyncResourceGuard<model>>`.
//! - `show`: private request struct, `RestEndpoint` impl (GET `path/{id}`), and
//!   `pub async fn <func>(tc, id) -> Result<model>`.
//! - `update`: private request struct, `RestEndpoint` impl (PATCH `path/{id}`,
//!   JSON body under `body_key`), and `pub async fn <func>(tc, id,
//!   <update_type>) -> Result<model>`.
//! - `list`: **public** request struct with `Option<String>` query fields,
//!   `RestEndpoint` impl (GET `path`), and `pub async fn <func>(tc, params) ->
//!   Result<Vec<model>>`.
//! - `delete`: private request struct, `RestEndpoint` impl (DELETE
//!   `path/{id}`), `impl DeletableResource for <model>` (requires `model` to
//!   have an `id: String` field), and `pub async fn <func>(tc, id) ->
//!   Result<()>`. Use `delete_impl` instead of `delete` when only the
//!   `DeletableResource` impl is wanted without a public delete function.
macro_rules! crud_endpoint {
    // Entry: one or more operation blocks.
    ($($op:ident { $($body:tt)* })+) => {
        $(crud_endpoint!(@ $op { $($body)* });)+
    };

    (@ create {
        request = $request:ident,
        func = $func:ident,
        path = $path:literal,
        body_key = $body_key:literal,
        create_type = $create_type:ty,
        model = $model:ty,
        response_key = $response_key:literal,
        service = $service:ident,
        api_version = ($major:literal, $minor:literal) $(,)?
    }) => {
        #[derive(Clone, Debug)]
        struct $request {
            body: $create_type,
        }

        impl ::openstack_sdk::api::rest_endpoint_prelude::RestEndpoint for $request {
            fn method(&self) -> ::http::Method {
                ::http::Method::POST
            }

            fn endpoint(&self) -> ::std::borrow::Cow<'static, str> {
                $path.into()
            }

            fn body(
                &self,
            ) -> ::std::result::Result<
                Option<(&'static str, Vec<u8>)>,
                ::openstack_sdk::api::rest_endpoint_prelude::BodyError,
            > {
                let mut params =
                    ::openstack_sdk::api::rest_endpoint_prelude::JsonBodyParams::default();
                params.push($body_key, ::serde_json::to_value(&self.body)?);
                params.into_body()
            }

            fn service_type(
                &self,
            ) -> ::openstack_sdk::api::rest_endpoint_prelude::ServiceType {
                ::openstack_sdk::api::rest_endpoint_prelude::ServiceType::$service
            }

            fn response_key(&self) -> Option<::std::borrow::Cow<'static, str>> {
                Some($response_key.into())
            }

            fn api_version(
                &self,
            ) -> Option<::openstack_sdk::api::rest_endpoint_prelude::ApiVersion> {
                Some(::openstack_sdk::api::rest_endpoint_prelude::ApiVersion::new(
                    $major, $minor,
                ))
            }
        }

        /// Create the resource, returning a guard that must be explicitly
        /// deleted with `.delete().await?` (see [`crate::guard`]).
        pub async fn $func(
            tc: &::std::sync::Arc<::openstack_sdk::AsyncOpenStack>,
            body: $create_type,
        ) -> ::eyre::Result<$crate::guard::AsyncResourceGuard<$model>> {
            use ::openstack_sdk::api::QueryAsync;
            let obj: $model = $request { body }.query_async(tc.as_ref()).await?;
            Ok($crate::guard::AsyncResourceGuard::new(obj, tc.clone()))
        }
    };

    (@ show {
        request = $request:ident,
        func = $func:ident,
        path = $path:literal,
        model = $model:ty,
        response_key = $response_key:literal,
        service = $service:ident,
        api_version = ($major:literal, $minor:literal) $(,)?
    }) => {
        #[derive(Clone, Debug)]
        struct $request {
            id: String,
        }

        impl ::openstack_sdk::api::rest_endpoint_prelude::RestEndpoint for $request {
            fn method(&self) -> ::http::Method {
                ::http::Method::GET
            }

            fn endpoint(&self) -> ::std::borrow::Cow<'static, str> {
                format!("{}/{}", $path, self.id).into()
            }

            fn service_type(
                &self,
            ) -> ::openstack_sdk::api::rest_endpoint_prelude::ServiceType {
                ::openstack_sdk::api::rest_endpoint_prelude::ServiceType::$service
            }

            fn response_key(&self) -> Option<::std::borrow::Cow<'static, str>> {
                Some($response_key.into())
            }

            fn api_version(
                &self,
            ) -> Option<::openstack_sdk::api::rest_endpoint_prelude::ApiVersion> {
                Some(::openstack_sdk::api::rest_endpoint_prelude::ApiVersion::new(
                    $major, $minor,
                ))
            }
        }

        /// Show a single resource by ID.
        pub async fn $func(
            tc: &::std::sync::Arc<::openstack_sdk::AsyncOpenStack>,
            id: impl Into<String>,
        ) -> ::eyre::Result<$model> {
            use ::openstack_sdk::api::QueryAsync;
            Ok($request { id: id.into() }.query_async(tc.as_ref()).await?)
        }
    };

    (@ update {
        request = $request:ident,
        func = $func:ident,
        path = $path:literal,
        body_key = $body_key:literal,
        update_type = $update_type:ty,
        model = $model:ty,
        response_key = $response_key:literal,
        service = $service:ident,
        api_version = ($major:literal, $minor:literal) $(,)?
    }) => {
        #[derive(Clone, Debug)]
        struct $request {
            id: String,
            body: $update_type,
        }

        impl ::openstack_sdk::api::rest_endpoint_prelude::RestEndpoint for $request {
            fn method(&self) -> ::http::Method {
                ::http::Method::PATCH
            }

            fn endpoint(&self) -> ::std::borrow::Cow<'static, str> {
                format!("{}/{}", $path, self.id).into()
            }

            fn body(
                &self,
            ) -> ::std::result::Result<
                Option<(&'static str, Vec<u8>)>,
                ::openstack_sdk::api::rest_endpoint_prelude::BodyError,
            > {
                let mut params =
                    ::openstack_sdk::api::rest_endpoint_prelude::JsonBodyParams::default();
                params.push($body_key, ::serde_json::to_value(&self.body)?);
                params.into_body()
            }

            fn service_type(
                &self,
            ) -> ::openstack_sdk::api::rest_endpoint_prelude::ServiceType {
                ::openstack_sdk::api::rest_endpoint_prelude::ServiceType::$service
            }

            fn response_key(&self) -> Option<::std::borrow::Cow<'static, str>> {
                Some($response_key.into())
            }

            fn api_version(
                &self,
            ) -> Option<::openstack_sdk::api::rest_endpoint_prelude::ApiVersion> {
                Some(::openstack_sdk::api::rest_endpoint_prelude::ApiVersion::new(
                    $major, $minor,
                ))
            }
        }

        /// Update the resource identified by `id`.
        pub async fn $func(
            tc: &::std::sync::Arc<::openstack_sdk::AsyncOpenStack>,
            id: &str,
            body: $update_type,
        ) -> ::eyre::Result<$model> {
            use ::openstack_sdk::api::QueryAsync;
            Ok($request {
                id: id.to_string(),
                body,
            }
            .query_async(tc.as_ref())
            .await?)
        }
    };

    (@ list {
        request = $request:ident,
        func = $func:ident,
        path = $path:literal,
        model = $model:ty,
        response_key = $response_key:literal,
        service = $service:ident,
        api_version = ($major:literal, $minor:literal),
        query = [$($query_field:ident),* $(,)?] $(,)?
    }) => {
        /// List request query parameters.
        #[derive(Clone, Debug, Default)]
        pub struct $request {
            $(pub $query_field: Option<String>,)*
        }

        impl ::openstack_sdk::api::rest_endpoint_prelude::RestEndpoint for $request {
            fn method(&self) -> ::http::Method {
                ::http::Method::GET
            }

            fn endpoint(&self) -> ::std::borrow::Cow<'static, str> {
                $path.into()
            }

            fn parameters(
                &self,
            ) -> ::openstack_sdk::api::rest_endpoint_prelude::QueryParams<'_> {
                let mut params =
                    ::openstack_sdk::api::rest_endpoint_prelude::QueryParams::default();
                $(params.push_opt(stringify!($query_field), self.$query_field.as_ref());)*
                params
            }

            fn service_type(
                &self,
            ) -> ::openstack_sdk::api::rest_endpoint_prelude::ServiceType {
                ::openstack_sdk::api::rest_endpoint_prelude::ServiceType::$service
            }

            fn response_key(&self) -> Option<::std::borrow::Cow<'static, str>> {
                Some($response_key.into())
            }

            fn api_version(
                &self,
            ) -> Option<::openstack_sdk::api::rest_endpoint_prelude::ApiVersion> {
                Some(::openstack_sdk::api::rest_endpoint_prelude::ApiVersion::new(
                    $major, $minor,
                ))
            }
        }

        /// List resources matching the query parameters.
        pub async fn $func(
            tc: &::std::sync::Arc<::openstack_sdk::AsyncOpenStack>,
            params: $request,
        ) -> ::eyre::Result<Vec<$model>> {
            use ::openstack_sdk::api::QueryAsync;
            Ok(params.query_async(tc.as_ref()).await?)
        }
    };

    // Delete with a public wrapper function.
    (@ delete {
        request = $request:ident,
        func = $func:ident,
        path = $path:literal,
        model = $model:ty,
        service = $service:ident,
        api_version = ($major:literal, $minor:literal) $(,)?
    }) => {
        crud_endpoint!(@ delete_impl {
            request = $request,
            path = $path,
            model = $model,
            service = $service,
            api_version = ($major, $minor),
        });

        /// Delete the resource identified by `id`.
        pub async fn $func(
            tc: &::std::sync::Arc<::openstack_sdk::AsyncOpenStack>,
            id: impl Into<String>,
        ) -> ::eyre::Result<()> {
            use ::openstack_sdk::api::QueryAsync;
            Ok(
                ::openstack_sdk::api::ignore($request { id: id.into() })
                    .query_async(tc.as_ref())
                    .await?,
            )
        }
    };

    // Delete without a public wrapper: only the request struct and the
    // `DeletableResource` impl used by `AsyncResourceGuard`.
    (@ delete_impl {
        request = $request:ident,
        path = $path:literal,
        model = $model:ty,
        service = $service:ident,
        api_version = ($major:literal, $minor:literal) $(,)?
    }) => {
        #[derive(Clone, Debug)]
        struct $request {
            id: String,
        }

        impl ::openstack_sdk::api::rest_endpoint_prelude::RestEndpoint for $request {
            fn method(&self) -> ::http::Method {
                ::http::Method::DELETE
            }

            fn endpoint(&self) -> ::std::borrow::Cow<'static, str> {
                format!("{}/{}", $path, self.id).into()
            }

            fn service_type(
                &self,
            ) -> ::openstack_sdk::api::rest_endpoint_prelude::ServiceType {
                ::openstack_sdk::api::rest_endpoint_prelude::ServiceType::$service
            }

            fn api_version(
                &self,
            ) -> Option<::openstack_sdk::api::rest_endpoint_prelude::ApiVersion> {
                Some(::openstack_sdk::api::rest_endpoint_prelude::ApiVersion::new(
                    $major, $minor,
                ))
            }
        }

        #[async_trait::async_trait]
        impl $crate::guard::DeletableResource for $model {
            async fn delete(
                &self,
                state: &::std::sync::Arc<::openstack_sdk::AsyncOpenStack>,
            ) -> ::eyre::Result<()> {
                use ::openstack_sdk::api::QueryAsync;
                Ok(::openstack_sdk::api::ignore($request {
                    id: self.id.clone(),
                })
                .query_async(state.as_ref())
                .await?)
            }
        }
    };
}

pub(crate) use crud_endpoint;

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    //! Compile-oriented expansion checks: each block below validates a
    //! distinct operation combination compiles and produces the expected
    //! request shapes. Wire behavior is covered by the live API tests.

    use openstack_sdk::api::rest_endpoint_prelude::RestEndpoint;
    use serde::{Deserialize, Serialize};

    /// Full CRUD-without-update combination (the v3 group shape).
    mod widgets {
        use super::*;

        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct Widget {
            pub id: String,
            pub name: String,
        }

        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct WidgetCreate {
            pub name: String,
        }

        crate::macros::crud_endpoint! {
            create {
                request = WidgetCreateApiRequest,
                func = create_widget,
                path = "widgets",
                body_key = "widget",
                create_type = WidgetCreate,
                model = Widget,
                response_key = "widget",
                service = Identity,
                api_version = (3, 0),
            }
            show {
                request = WidgetShowApiRequest,
                func = get_widget,
                path = "widgets",
                model = Widget,
                response_key = "widget",
                service = Identity,
                api_version = (3, 0),
            }
            list {
                request = WidgetListRequest,
                func = list_widgets,
                path = "widgets",
                model = Widget,
                response_key = "widgets",
                service = Identity,
                api_version = (3, 0),
                query = [domain_id, name],
            }
            delete {
                request = WidgetDeleteApiRequest,
                func = delete_widget,
                path = "widgets",
                model = Widget,
                service = Identity,
                api_version = (3, 0),
            }
        }

        fn create_request() -> WidgetCreateApiRequest {
            WidgetCreateApiRequest {
                body: WidgetCreate { name: "n".into() },
            }
        }

        #[test]
        fn create_request_shape() {
            let req = create_request();
            assert_eq!(req.method(), http::Method::POST);
            assert_eq!(req.endpoint(), "widgets");
            assert_eq!(req.response_key().as_deref(), Some("widget"));
            let (content_type, body) = req.body().ok().flatten().unwrap_or(("missing", Vec::new()));
            assert_eq!(content_type, "application/json");
            assert_eq!(String::from_utf8_lossy(&body), r#"{"widget":{"name":"n"}}"#);
        }

        #[test]
        fn show_request_interpolates_id() {
            let req = WidgetShowApiRequest { id: "abc".into() };
            assert_eq!(req.method(), http::Method::GET);
            assert_eq!(req.endpoint(), "widgets/abc");
        }

        #[test]
        fn delete_request_interpolates_id() {
            let req = WidgetDeleteApiRequest { id: "abc".into() };
            assert_eq!(req.method(), http::Method::DELETE);
            assert_eq!(req.endpoint(), "widgets/abc");
            assert_eq!(req.response_key(), None);
        }

        #[test]
        fn list_request_defaults_and_endpoint() {
            let req = WidgetListRequest {
                domain_id: Some("did".into()),
                ..Default::default()
            };
            assert_eq!(req.method(), http::Method::GET);
            assert_eq!(req.endpoint(), "widgets");
            assert_eq!(req.response_key().as_deref(), Some("widgets"));
            assert!(req.name.is_none());
        }
    }

    /// Create/update/delete_impl combination with a distinct list item
    /// type and no public delete function (the v3 user shape).
    mod gadgets {
        use super::*;

        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct Gadget {
            pub id: String,
        }

        /// Reduced representation returned by list (like `ProjectShort`).
        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct GadgetShort {
            pub id: String,
        }

        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct GadgetCreate {
            pub name: String,
        }

        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct GadgetUpdate {
            pub name: Option<String>,
        }

        crate::macros::crud_endpoint! {
            create {
                request = GadgetCreateApiRequest,
                func = create_gadget,
                path = "gadgets",
                body_key = "gadget",
                create_type = GadgetCreate,
                model = Gadget,
                response_key = "gadget",
                service = Identity,
                api_version = (4, 0),
            }
            update {
                request = GadgetUpdateApiRequest,
                func = update_gadget,
                path = "gadgets",
                body_key = "gadget",
                update_type = GadgetUpdate,
                model = Gadget,
                response_key = "gadget",
                service = Identity,
                api_version = (4, 0),
            }
            list {
                request = GadgetListRequest,
                func = list_gadgets,
                path = "gadgets",
                model = GadgetShort,
                response_key = "gadgets",
                service = Identity,
                api_version = (4, 0),
                query = [name],
            }
            delete_impl {
                request = GadgetDeleteApiRequest,
                path = "gadgets",
                model = Gadget,
                service = Identity,
                api_version = (4, 0),
            }
        }
    }

    /// A single standalone operation must also expand.
    mod single_op {
        use super::*;

        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct Sprocket {
            pub id: String,
        }

        crate::macros::crud_endpoint! {
            show {
                request = SprocketShowApiRequest,
                func = get_sprocket,
                path = "sprockets",
                model = Sprocket,
                response_key = "sprocket",
                service = Identity,
                api_version = (3, 0),
            }
        }
    }
}
