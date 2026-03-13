// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
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
use mockall::mock;

use crate::application_credential::ApplicationCredentialApi;
use crate::application_credential::ApplicationCredentialProviderError;
use crate::application_credential::types::*;
use crate::config::Config;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;

mock! {
    pub ApplicationCredentialProvider {
        pub fn new(cfg: &Config, plugin_manager: &PluginManager) -> Result<Self, ApplicationCredentialProviderError>;
    }

    #[async_trait]
    impl ApplicationCredentialApi for ApplicationCredentialProvider {

        async fn create_application_credential(
            &self,
            state: &ServiceState,
            rec: ApplicationCredentialCreate,
        ) -> Result<ApplicationCredentialCreateResponse, ApplicationCredentialProviderError>;

        async fn get_application_credential<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<ApplicationCredential>, ApplicationCredentialProviderError>;

        async fn list_application_credentials(
            &self,
            state: &ServiceState,
            params: &ApplicationCredentialListParameters,
        ) -> Result<Vec<ApplicationCredential>, ApplicationCredentialProviderError>;
    }
}
