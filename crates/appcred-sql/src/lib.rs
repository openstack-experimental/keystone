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
//! # OpenStack Keystone Application Credential SQL driver

use async_trait::async_trait;

use openstack_keystone_core::application_credential::{
    ApplicationCredentialProviderError, backend::ApplicationCredentialBackend,
};
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core_types::application_credential::*;

mod application_credential;
pub mod entity;

/// SQL backend provider implementing the ApplicationCredentialBackend
/// interface.
#[derive(Default)]
pub struct SqlBackend {}

#[async_trait]
impl ApplicationCredentialBackend for SqlBackend {
    /// Create a new application credential.
    async fn create_application_credential(
        &self,
        state: &ServiceState,
        rec: ApplicationCredentialCreate,
    ) -> Result<ApplicationCredentialCreateResponse, ApplicationCredentialProviderError> {
        Ok(application_credential::create(&state.config, &state.db, rec).await?)
    }

    /// Get a single application credential by ID.
    async fn get_application_credential<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<ApplicationCredential>, ApplicationCredentialProviderError> {
        Ok(application_credential::get(&state.db, id).await?)
    }

    /// List application credentials.
    async fn list_application_credentials(
        &self,
        state: &ServiceState,
        params: &ApplicationCredentialListParameters,
    ) -> Result<Vec<ApplicationCredential>, ApplicationCredentialProviderError> {
        Ok(application_credential::list(&state.db, params).await?)
    }
}
