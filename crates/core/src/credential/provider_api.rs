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

use openstack_keystone_core_types::credential::*;

use crate::auth::ExecutionContext;
use crate::credential::error::CredentialProviderError;

/// Credentials API (ADR 0019).
#[async_trait]
pub trait CredentialApi: Send + Sync {
    /// Create a new credential.
    ///
    /// `rec.user_id` must already be resolved by the caller: defaulted to the
    /// authenticated user under user scope, or rejected with
    /// `CredentialProviderError::MissingUserId` if absent under system scope
    /// (ADR 0019 §2).
    async fn create_credential<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        rec: CredentialCreate,
    ) -> Result<Credential, CredentialProviderError>;

    /// Get a single credential by ID.
    async fn get_credential<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Credential>, CredentialProviderError>;

    /// Look up a credential by the plaintext EC2 access key.
    async fn get_credential_by_ec2_access<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        access: &'a str,
    ) -> Result<Option<Credential>, CredentialProviderError>;

    /// List credentials matching the given driver-level hints. Note: this
    /// does not perform the second, per-item `identity:get_credential`
    /// policy pass required by ADR 0019 §2 (CVE-2019-19687) — that is the
    /// API layer's responsibility, since it is the layer with access to the
    /// policy engine.
    async fn list_credentials<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &CredentialListParameters,
    ) -> Result<Vec<Credential>, CredentialProviderError>;

    /// List all credentials owned by a user, optionally filtered by type.
    async fn list_credentials_for_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
        r#type: Option<&'a str>,
    ) -> Result<Vec<Credential>, CredentialProviderError>;

    /// Update a credential.
    async fn update_credential<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
        rec: CredentialUpdate,
    ) -> Result<Credential, CredentialProviderError>;

    /// Delete a credential by ID.
    async fn delete_credential<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), CredentialProviderError>;

    /// Delete all credentials owned by a user.
    async fn delete_credentials_for_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<(), CredentialProviderError>;

    /// Delete all credentials bound to a project.
    async fn delete_credentials_for_project<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<(), CredentialProviderError>;
}
