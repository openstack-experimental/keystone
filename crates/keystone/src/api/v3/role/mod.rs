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
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

mod create;
mod list;
mod show;
pub mod types;

/// OpenApi specification for the roles.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name="roles", description=r#"OpenStack services typically determine whether a user’s API request should be allowed using Role Based Access Control (RBAC). For OpenStack this means the service compares the roles that user has on the project (as indicated by the roles in the token), against the roles required for the API in question (as defined in the service’s policy file). A user obtains roles on a project by having these assigned to them via the Identity service API.

Roles must initially be created as entities via the Identity services API and, once created, can then be assigned. You can assign roles to a user or group on a project, including projects owned by other domains. You can also assign roles to a user or group on a domain, although this is only currently relevant for using a domain scoped token to execute domain-level Identity service API requests."#),
        (name="role_assignments", description=r#"The creation, checking and deletion of role assignments is done with each of the attributes being specified in the URL. For example to assign a role to a user on a project:

```
PUT /v3/projects/{project_id}/users/{user_id}/roles/{role_id}
```

You can also list roles assigned to the system, or to a specified domain, project, or user using this form of API, however a more generalized API for list assignments is provided where query parameters are used to filter the set of assignments returned in the collection. For example:

- List role assignments for the specified user:

  ```
  GET /role_assignments?user.id={user_id}
  ```

- List role assignments for the specified project:

  ```
  GET /role_assignments?scope.project.id={project_id}
  ```

- List system role assignments for a specific user:

  ```
  GET /role_assignments?scope.system=all?user.id={user_id}
  ```

- List system role assignments for all users and groups:

  ```
  GET /role_assignments?scope.system=all
  ```

Since Identity API v3.10, you can grant role assignments to users and groups on an entity called the system. The role assignment API also supports listing and filtering role assignments on the system.

Since Identity API v3.6, you can also list all role assignments within a tree of projects, for example the following would list all role assignments for a specified project and its sub-projects:

```
GET /role_assignments?scope.project.id={project_id}&include_subtree=true
```

If you specify include_subtree=true, you must also specify the scope.project.id. Otherwise, this call returns the Bad Request (400) response code.

Each role assignment entity in the collection contains a link to the assignment that created the entity.

As mentioned earlier, role assignments can be made to a user or a group on a particular project, domain, or the entire system. A user who is a member of a group that has a role assignment, will also be treated as having that role assignment by virtue of their group membership. The effective role assignments of a user (on a given project or domain) therefore consists of any direct assignments they have, plus any they gain by virtue of membership of groups that also have assignments on the given project or domain. This set of effective role assignments is what is placed in the token for reference by services wishing to check policy. You can list the effective role assignments using the effective query parameter at the user, project, and domain level:

- Determine what a user can actually do:

  ```
  GET /role_assignments?user.id={user_id}&effective
  ```

- Get the equivalent set of role assignments that are included in a project-scoped token response:

  ```
  GET /role_assignments?user.id={user_id}&scope.project.id={project_id}&effective
  ```

When listing in effective mode, since the group assignments have been effectively expanded out into assignments for each user, the group role assignment entities themselves are not returned in the collection. However, in the response, the links entity section for each assignment gained by virtue of group membership will contain a URL that enables access to the membership of the group.

By default only the IDs of entities are returned in collections from the role_assignment API calls. The names of entities may also be returned, in addition to the IDs, by using the include_names query parameter on any of these calls, for example:

- List role assignments including names:

  ```
  GET /role_assignments?include_names
  ```
"#),
    )
)]
pub struct ApiDoc;

pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list, create::create))
        .routes(routes!(show::show))
}

#[cfg(test)]
mod tests {
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;

    use crate::assignment::MockAssignmentProvider;
    use crate::config::Config;
    use crate::keystone::{Service, ServiceState};
    use crate::policy::MockPolicyFactory;
    use crate::provider::Provider;
    use crate::token::{MockTokenProvider, Token, UnscopedPayload};

    pub fn get_mocked_state(assignment_mock: MockAssignmentProvider) -> ServiceState {
        let mut token_mock = MockTokenProvider::default();
        token_mock.expect_validate_token().returning(|_, _, _, _| {
            Ok(Token::Unscoped(UnscopedPayload {
                user_id: "bar".into(),
                ..Default::default()
            }))
        });
        token_mock
            .expect_expand_token_information()
            .returning(|_, _| {
                Ok(Token::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });

        let provider = Provider::mocked_builder()
            .assignment(assignment_mock)
            .token(token_mock)
            .build()
            .unwrap();

        Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        )
    }
}
