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
//! # Project API
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

mod create;
mod delete;
pub mod types;

/// OpenApi specification for the project API.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name="projects", description=r#"A project is the base unit of resource ownership. Resources are owned by a specific project. A project is owned by a specific domain.

(Since Identity API v3.4) You can create a hierarchy of projects by setting a parent_id when you create a project. All projects in a hierarchy must be owned by the same domain.

(Since Identity API v3.6) Projects may, in addition to acting as containers for OpenStack resources, act as a domain (by setting the attribute is_domain to true), in which case it provides a namespace in which users, groups and other projects can be created. In fact, a domain created using the POST /domains API will actually be represented as a project with is_domain set to true with no parent (parent_id is null).

Given this, all projects are considered part of a project hierarchy. Projects created in a domain prior to v3.6 are represented as a two-level hierarchy, with a project that has is_domain set to true as the root and all other projects referencing the root as their parent.

A project acting as a domain can potentially also act as a container for OpenStack resources, although this depends on whether the policy rule for the relevant resource creation allows this.

# Note

A project's name must be unique within a domain and no more than 64 characters. A project's name must be able to be sent within valid JSON, which could be any UTF-8 character. However, this is constrained to the given backend where project names are stored. For instance, MySQL's restrictions states that UTF-8 support is constrained to the characters in the Basic Multilingual Plane (BMP). Supplementary characters are not permitted. Note that this last restriction is generally true for all names within resources of the Identity API. Creating a project without using a domain scoped token, i.e. using a project scoped token or a system scoped token, and also without specifying a domain or domain_id, the project will automatically be created on the default domain.
"#),
    )
)]
pub struct ApiDoc;

pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(create::create))
        .routes(routes!(delete::remove))
}
