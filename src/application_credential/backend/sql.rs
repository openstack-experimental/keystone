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
//! # Application Credential SQL driver
use async_trait::async_trait;

use super::super::types::*;
use crate::application_credential::{
    ApplicationCredentialProviderError, backend::ApplicationCredentialBackend,
};
use crate::config::Config;
use crate::keystone::ServiceState;

mod application_credential;

/// SQL backend provider implementing the ApplicationCredentialBackend
/// interface.
#[derive(Clone, Debug, Default)]
pub struct SqlBackend {
    /// Config.
    pub config: Config,
}

#[async_trait]
impl ApplicationCredentialBackend for SqlBackend {
    /// Set config
    fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// Create a new application credential.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_application_credential(
        &self,
        state: &ServiceState,
        rec: ApplicationCredentialCreate,
    ) -> Result<ApplicationCredentialCreateResponse, ApplicationCredentialProviderError> {
        Ok(application_credential::create(&state.config, &state.db, rec).await?)
    }

    /// Get a single application credential by ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_application_credential<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<ApplicationCredential>, ApplicationCredentialProviderError> {
        Ok(application_credential::get(&state.db, id).await?)
    }

    /// List application credentials.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_application_credentials(
        &self,
        state: &ServiceState,
        params: &ApplicationCredentialListParameters,
    ) -> Result<Vec<ApplicationCredential>, ApplicationCredentialProviderError> {
        Ok(application_credential::list(&state.db, params).await?)
    }
}
