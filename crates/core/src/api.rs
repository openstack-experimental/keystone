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

pub mod auth;
pub mod common;
pub mod error;
pub mod types;
pub mod v3;
pub mod v4;

pub use error::KeystoneApiError;

#[cfg(test)]
pub(crate) mod tests {
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;

    use crate::config::Config;
    use crate::identity::types::UserResponseBuilder;
    use crate::keystone::{Service, ServiceState};
    use crate::policy::{MockPolicy, PolicyError, PolicyEvaluationResult};
    use crate::provider::ProviderBuilder;
    use crate::token::{MockTokenProvider, Token, UnscopedPayload};

    pub fn get_mocked_state(
        provider_builder: ProviderBuilder,
        policy_allowed: bool,
        policy_allowed_see_other_domains: Option<bool>,
        skip_default_token_provider: Option<bool>,
    ) -> ServiceState {
        let provider = if !skip_default_token_provider.is_some_and(|x| x) {
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
            provider_builder.mock_token(token_mock)
        } else {
            provider_builder
        }
        .build()
        .unwrap();

        let mut policy_enforcer_mock = MockPolicy::default();

        policy_enforcer_mock
            .expect_enforce()
            .returning(move |_, _, _, _| {
                if policy_allowed {
                    if policy_allowed_see_other_domains.is_some_and(|x| x) {
                        Ok(PolicyEvaluationResult::allowed_admin())
                    } else {
                        Ok(PolicyEvaluationResult::allowed())
                    }
                } else {
                    Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()))
                }
            });

        Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(policy_enforcer_mock),
            )
            .unwrap(),
        )
    }
}
