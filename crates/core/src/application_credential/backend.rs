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
//! # Application credential provider backend

use async_trait::async_trait;

use openstack_keystone_core_types::application_credential::*;

use crate::application_credential::ApplicationCredentialProviderError;
use crate::keystone::ServiceState;

/// Application Credential backend driver interface.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait ApplicationCredentialBackend: Send + Sync {
    /// Create a standalone access rule owned by a user.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `rule`: The access rule to create (its `user_id` identifies the owner).
    ///
    /// # Returns
    /// - `Result<AccessRule, ApplicationCredentialProviderError>` - The created
    ///   access rule or an error.
    async fn create_access_rule(
        &self,
        state: &ServiceState,
        rule: AccessRuleCreate,
    ) -> Result<AccessRule, ApplicationCredentialProviderError>;

    /// Create a new application credential.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `rec`: The application credential creation request.
    ///
    /// # Returns
    /// - `Result<ApplicationCredentialCreateResponse,
    ///   ApplicationCredentialProviderError>` - The creation response or an
    ///   error.
    async fn create_application_credential(
        &self,
        state: &ServiceState,
        rec: ApplicationCredentialCreate,
    ) -> Result<ApplicationCredentialCreateResponse, ApplicationCredentialProviderError>;

    /// Delete a user's access rule by its ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `user_id`: The ID of the user owning the access rule.
    /// - `id`: The ID of the access rule.
    ///
    /// # Returns
    /// - `Result<(), ApplicationCredentialProviderError>` - Unit on success, or
    ///   an error.
    async fn delete_access_rule<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        id: &'a str,
    ) -> Result<(), ApplicationCredentialProviderError>;

    /// Get a user's access rule by its ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `user_id`: The ID of the user owning the access rule.
    /// - `id`: The ID of the access rule.
    ///
    /// # Returns
    /// - `Result<Option<AccessRule>, ApplicationCredentialProviderError>` - The
    ///   access rule if found, or an error.
    async fn get_access_rule<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        id: &'a str,
    ) -> Result<Option<AccessRule>, ApplicationCredentialProviderError>;

    /// Get a single application credential by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The ID of the application credential.
    ///
    /// # Returns
    /// - `Result<Option<ApplicationCredential>,
    ///   ApplicationCredentialProviderError>` - The credential if found, or an
    ///   error.
    async fn get_application_credential<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<ApplicationCredential>, ApplicationCredentialProviderError>;

    /// List all access rules owned by a user.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `user_id`: The ID of the user owning the access rules.
    ///
    /// # Returns
    /// - `Result<Vec<AccessRule>, ApplicationCredentialProviderError>` - A list
    ///   of access rules or an error.
    async fn list_access_rules<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<AccessRule>, ApplicationCredentialProviderError>;

    /// List application credentials.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: Parameters for filtering the list of credentials.
    ///
    /// # Returns
    /// - `Result<Vec<ApplicationCredential>,
    ///   ApplicationCredentialProviderError>` - A list of application
    ///   credentials or an error.
    async fn list_application_credentials(
        &self,
        state: &ServiceState,
        params: &ApplicationCredentialListParameters,
    ) -> Result<Vec<ApplicationCredential>, ApplicationCredentialProviderError>;
}
