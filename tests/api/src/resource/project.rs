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
//! v3 project CRUD helpers, generated with [`crate::macros::crud_endpoint`].

use openstack_keystone_api_types::v3::project::*;

use crate::macros::crud_endpoint;

crud_endpoint! {
    create {
        request = ProjectCreateRequest,
        func = create_project,
        path = "projects",
        body_key = "project",
        create_type = ProjectCreate,
        model = Project,
        response_key = "project",
        service = Identity,
        api_version = (3, 0),
    }
    show {
        request = ProjectShowRequest,
        func = get_project,
        path = "projects",
        model = Project,
        response_key = "project",
        service = Identity,
        api_version = (3, 0),
    }
    update {
        request = ProjectUpdateRequest,
        func = update_project,
        path = "projects",
        body_key = "project",
        update_type = ProjectUpdate,
        model = Project,
        response_key = "project",
        service = Identity,
        api_version = (3, 0),
    }
    list {
        request = ProjectListRequest,
        func = list_projects,
        path = "projects",
        model = Project,
        response_key = "projects",
        service = Identity,
        api_version = (3, 0),
        query = [domain_id, ids, name, enabled],
    }
    delete {
        request = ProjectDeleteRequest,
        func = delete_project,
        path = "projects",
        model = Project,
        service = Identity,
        api_version = (3, 0),
    }
}

/// Hierarchy flags of the project show call
/// (`GET /v3/projects/{project_id}?parents_as_list&...`).
#[derive(Clone, Copy, Debug, Default)]
pub struct ProjectHierarchyQuery {
    pub parents_as_list: bool,
    pub parents_as_ids: bool,
    pub subtree_as_list: bool,
    pub subtree_as_ids: bool,
}

#[derive(Clone, Debug)]
struct ProjectHierarchyShowRequest {
    id: String,
    query: ProjectHierarchyQuery,
}

impl ::openstack_sdk::api::rest_endpoint_prelude::RestEndpoint for ProjectHierarchyShowRequest {
    fn method(&self) -> ::http::Method {
        ::http::Method::GET
    }

    fn endpoint(&self) -> ::std::borrow::Cow<'static, str> {
        format!("projects/{}", self.id).into()
    }

    fn parameters(&self) -> ::openstack_sdk::api::rest_endpoint_prelude::QueryParams<'_> {
        let mut params = ::openstack_sdk::api::rest_endpoint_prelude::QueryParams::default();
        // Presence of the key (with an empty value) enables the flag.
        for (name, set) in [
            ("parents_as_list", self.query.parents_as_list),
            ("parents_as_ids", self.query.parents_as_ids),
            ("subtree_as_list", self.query.subtree_as_list),
            ("subtree_as_ids", self.query.subtree_as_ids),
        ] {
            if set {
                params.push(name, "");
            }
        }
        params
    }

    fn service_type(&self) -> ::openstack_sdk::api::rest_endpoint_prelude::ServiceType {
        ::openstack_sdk::api::rest_endpoint_prelude::ServiceType::Identity
    }

    fn response_key(&self) -> Option<::std::borrow::Cow<'static, str>> {
        Some("project".into())
    }

    fn api_version(&self) -> Option<::openstack_sdk::api::rest_endpoint_prelude::ApiVersion> {
        Some(::openstack_sdk::api::rest_endpoint_prelude::ApiVersion::new(3, 0))
    }
}

/// Show a project together with the requested hierarchy data. Returns the raw
/// `project` JSON object, including the `parents` and `subtree` members.
pub async fn get_project_hierarchy(
    tc: &::std::sync::Arc<::openstack_sdk::AsyncOpenStack>,
    id: impl Into<String>,
    query: ProjectHierarchyQuery,
) -> ::eyre::Result<::serde_json::Value> {
    use ::openstack_sdk::api::QueryAsync;
    Ok(ProjectHierarchyShowRequest {
        id: id.into(),
        query,
    }
    .query_async(tc.as_ref())
    .await?)
}
