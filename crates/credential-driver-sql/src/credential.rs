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
//! # Credentials SQL backend (ADR 0019)

mod create;
mod delete;
pub(crate) mod get;
mod list;
mod update;

use async_trait::async_trait;

use openstack_keystone_core::credential::{CredentialProviderError, backend::CredentialBackend};
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core_types::credential::*;

use crate::SqlBackend;

#[async_trait]
impl CredentialBackend for SqlBackend {
    async fn create_credential(
        &self,
        state: &ServiceState,
        rec: CredentialCreate,
    ) -> Result<Credential, CredentialProviderError> {
        let cfg = state.config_manager.config.read().await;
        create::create(&cfg, &state.db, rec).await
    }

    async fn get_credential<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Credential>, CredentialProviderError> {
        let cfg = state.config_manager.config.read().await;
        get::get(&cfg, &state.db, id).await
    }

    async fn get_credential_by_ec2_access<'a>(
        &self,
        state: &ServiceState,
        access: &'a str,
    ) -> Result<Option<Credential>, CredentialProviderError> {
        let cfg = state.config_manager.config.read().await;
        get::get_by_ec2_access(&cfg, &state.db, access).await
    }

    async fn list_credentials(
        &self,
        state: &ServiceState,
        params: &CredentialListParameters,
    ) -> Result<Vec<Credential>, CredentialProviderError> {
        let cfg = state.config_manager.config.read().await;
        list::list(&cfg, &state.db, params).await
    }

    async fn list_credentials_for_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        r#type: Option<&'a str>,
    ) -> Result<Vec<Credential>, CredentialProviderError> {
        let cfg = state.config_manager.config.read().await;
        list::list_for_user(&cfg, &state.db, user_id, r#type).await
    }

    async fn update_credential<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        rec: CredentialUpdate,
    ) -> Result<Credential, CredentialProviderError> {
        let cfg = state.config_manager.config.read().await;
        update::update(&cfg, &state.db, id, rec).await
    }

    async fn delete_credential<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), CredentialProviderError> {
        delete::delete(&state.db, id).await
    }

    async fn delete_credentials_for_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), CredentialProviderError> {
        delete::delete_for_user(&state.db, user_id).await
    }

    async fn delete_credentials_for_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<(), CredentialProviderError> {
        delete::delete_for_project(&state.db, project_id).await
    }
}
