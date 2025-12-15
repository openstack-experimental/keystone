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

//! # Federation attribute mappings API
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

mod create;
mod delete;
mod list;
mod show;
mod update;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list, create::create))
        .routes(routes!(show::show, update::update, delete::remove))
}

#[cfg(test)]
mod tests {

    use sea_orm::DatabaseConnection;
    use std::sync::Arc;

    use crate::config::Config;
    use crate::federation::MockFederationProvider;
    use crate::keystone::{Service, ServiceState};
    use crate::policy::{MockPolicy, MockPolicyFactory, PolicyError, PolicyEvaluationResult};
    use crate::provider::Provider;
    use crate::token::{MockTokenProvider, Token, UnscopedPayload};

    pub(super) fn get_mocked_state(
        federation_mock: MockFederationProvider,
        policy_allowed: bool,
    ) -> ServiceState {
        let mut token_mock = MockTokenProvider::default();
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
                    ..Default::default()
                }))
            });

        let provider = Provider::mocked_builder()
            .federation(federation_mock)
            .token(token_mock)
            .build()
            .unwrap();

        let mut policy_factory_mock = MockPolicyFactory::default();
        if policy_allowed {
            policy_factory_mock.expect_instantiate().returning(|| {
                let mut policy_mock = MockPolicy::default();
                policy_mock
                    .expect_enforce()
                    .returning(|_, _, _, _| Ok(PolicyEvaluationResult::allowed()));
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
