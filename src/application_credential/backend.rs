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
pub mod error;
pub mod sql;

use async_trait::async_trait;
use dyn_clone::DynClone;

use crate::application_credential::ApplicationCredentialProviderError;
use crate::application_credential::types::*;
use crate::config::Config;
use crate::keystone::ServiceState;

pub use sql::SqlBackend;

/// Application Credential backend driver interface.
#[async_trait]
pub trait ApplicationCredentialBackend: DynClone + Send + Sync + std::fmt::Debug {
    /// Set config
    fn set_config(&mut self, config: Config);

    /// Create a new application credential.
    async fn create_application_credential(
        &self,
        state: &ServiceState,
        rec: ApplicationCredentialCreate,
    ) -> Result<ApplicationCredentialCreateResponse, ApplicationCredentialProviderError>;

    /// Get a single application credential by ID.
    async fn get_application_credential<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<ApplicationCredential>, ApplicationCredentialProviderError>;

    /// List application credentials.
    async fn list_application_credentials(
        &self,
        state: &ServiceState,
        params: &ApplicationCredentialListParameters,
    ) -> Result<Vec<ApplicationCredential>, ApplicationCredentialProviderError>;
}

dyn_clone::clone_trait_object!(ApplicationCredentialBackend);
