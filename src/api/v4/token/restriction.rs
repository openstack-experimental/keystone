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

//! Token restrictions API
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

    use sea_orm::DatabaseConnection;
    use std::sync::Arc;

    use crate::config::Config;

    use crate::identity::types::UserResponse;
    use crate::keystone::{Service, ServiceState};
    use crate::policy::{MockPolicy, MockPolicyFactory, PolicyError, PolicyEvaluationResult};
    use crate::provider::Provider;
    use crate::token::{MockTokenProvider, Token, UnscopedPayload};

    pub(crate) fn get_mocked_state(
        mut token_mock: MockTokenProvider,
        policy_allowed: bool,
        policy_allowed_see_other_domains: Option<bool>,
    ) -> ServiceState {
        token_mock
            .expect_validate_token()
            .returning(|_, _, _, _, _| {
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
                    user: Some(UserResponse {
                        id: "bar".into(),
                        domain_id: "udid".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }))
            });

        let provider = Provider::mocked_builder()
            .token(token_mock)
            .build()
            .unwrap();

        let mut policy_factory_mock = MockPolicyFactory::default();
        if policy_allowed {
            policy_factory_mock.expect_instantiate().returning(move || {
                let mut policy_mock = MockPolicy::default();
                if policy_allowed_see_other_domains.is_some_and(|x| x) {
                    policy_mock
                        .expect_enforce()
                        .returning(|_, _, _, _| Ok(PolicyEvaluationResult::allowed_admin()));
                } else {
                    policy_mock
                        .expect_enforce()
                        .returning(|_, _, _, _| Ok(PolicyEvaluationResult::allowed()));
                }
                Ok(policy_mock)
            });
        } else {
            policy_factory_mock.expect_instantiate().returning(|| {
                let mut policy_mock = MockPolicy::default();
                policy_mock.expect_enforce().returning(|_, _, _, _| {
                    Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()))
                });
                Ok(policy_mock)
            });
        }
        Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                policy_factory_mock,
            )
            .unwrap(),
        )
    }
}
