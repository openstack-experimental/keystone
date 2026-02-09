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
//! Authentication API.
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

mod common;
mod create;
mod delete;
mod show;
mod token_impl;
pub mod types;

pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(show::show, create::create, delete::delete))
}

#[cfg(test)]
mod tests {

    use crate::policy::{MockPolicy, MockPolicyFactory, PolicyEvaluationResult};

    pub(super) fn get_policy_factory_mock() -> MockPolicyFactory {
        let mut policy_factory_mock = MockPolicyFactory::default();
        policy_factory_mock.expect_instantiate().returning(|| {
            let mut policy_mock = MockPolicy::default();
            policy_mock
                .expect_enforce()
                .returning(|_, _, _, _| Ok(PolicyEvaluationResult::allowed()));
            Ok(policy_mock)
        });
        policy_factory_mock
    }
}
