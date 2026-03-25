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

//! Token restrictions API.
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

mod create;
mod delete;
mod list;
mod show;
mod update;

/// OpenApi specification for the token restriction api.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name="token_restriction", description=r#"Token restrictions API.

Token restrictions allow controlling multiple aspects of the authentication and authorization.

- `allow_rescope` controls whether it is allowed to change the scope of the token. That is by default possible for normal (i.e. password) authentication, is forbidden for the application credentials and may need to be also forbidden for the JWT based authentication.

- `allow_renew` controls whether it is possible to renew the token (get a new token from existing token). This is most likely undisired for the JWT auth.

- `project_id` may control that this token can be only issued for the fixed project scope.

- `user_id` may specify the fixed user_id that will be used when issuing the token independently of the authentication. This is useful for Service Accounts.

- `roles` binds the roles of the issued token on the scope. Using this bypasses necessity to grant the roles explicitly to the user.

        "#),
    )
)]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(show::show, delete::remove, update::update))
        .routes(routes!(list::list, create::create))
}

#[cfg(test)]
mod tests {

    use openstack_keystone_core_types::identity::*;

    use crate::token::{MockTokenProvider, Token, UnscopedPayload};

    pub(crate) fn get_token_provider_mock_with_mocks() -> MockTokenProvider {
        let mut token_mock = MockTokenProvider::default();
        token_mock.expect_validate_token().returning(|_, _, _, _| {
            Ok(Token::Unscoped(UnscopedPayload {
                user_id: "bar".into(),
                user: Some(
                    UserResponseBuilder::default()
                        .id("bar")
                        .domain_id("udid")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ),
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
        token_mock
    }
}
