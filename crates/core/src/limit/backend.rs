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

use async_trait::async_trait;

use openstack_keystone_core_types::limit::*;

use crate::keystone::ServiceState;
use crate::limit::error::LimitProviderError;

/// Limit backend driver interface.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait LimitBackend: Send + Sync {
    /// Create registered limits atomically (all or none).
    async fn create_registered_limits<'a>(
        &self,
        state: &ServiceState,
        limits: Vec<RegisteredLimitCreate>,
    ) -> Result<Vec<RegisteredLimit>, LimitProviderError>;

    /// Get a registered limit by ID.
    async fn get_registered_limit<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<RegisteredLimit>, LimitProviderError>;

    /// List registered limits.
    async fn list_registered_limits<'a>(
        &self,
        state: &ServiceState,
        params: &RegisteredLimitListParameters,
    ) -> Result<Vec<RegisteredLimit>, LimitProviderError>;

    /// Update a registered limit.
    async fn update_registered_limit<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: RegisteredLimitUpdate,
    ) -> Result<RegisteredLimit, LimitProviderError>;

    /// Delete a registered limit.
    async fn delete_registered_limit<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), LimitProviderError>;

    /// Create limits atomically (all or none).
    async fn create_limits<'a>(
        &self,
        state: &ServiceState,
        limits: Vec<LimitCreate>,
    ) -> Result<Vec<Limit>, LimitProviderError>;

    /// Get a limit by ID.
    async fn get_limit<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Limit>, LimitProviderError>;

    /// List limits.
    async fn list_limits<'a>(
        &self,
        state: &ServiceState,
        params: &LimitListParameters,
    ) -> Result<Vec<Limit>, LimitProviderError>;

    /// Update a limit.
    async fn update_limit<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: LimitUpdate,
    ) -> Result<Limit, LimitProviderError>;

    /// Delete a limit.
    async fn delete_limit<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), LimitProviderError>;

    /// Delete all limits of the project.
    async fn delete_limits_by_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<(), LimitProviderError>;

    /// Delete all limits of the domain.
    async fn delete_limits_by_domain<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<(), LimitProviderError>;
}
