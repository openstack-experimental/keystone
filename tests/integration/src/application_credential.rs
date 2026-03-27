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

use eyre::Report;
use openstack_keystone_core_types::application_credential::ApplicationCredentialCreate;
use std::sync::Arc;

use openstack_keystone::application_credential::ApplicationCredentialApi;
use openstack_keystone_core::keystone::Service;
use openstack_keystone_core_types::application_credential as types;

mod create;
mod get;
mod list;

//impl_deleter!(Service, ApplicationCredential, get_application_credential_provider, delete_application_credential);
//
async fn create_application_credential(
    state: &Arc<Service>,
    data: ApplicationCredentialCreate,
) -> Result<types::ApplicationCredentialCreateResponse, Report> {
    let res = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(state, data)
        .await?;
    Ok(res)
}
