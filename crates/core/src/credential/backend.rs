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
//! # Credential provider backend

use async_trait::async_trait;

use openstack_keystone_core_types::credential::*;

use crate::credential::CredentialProviderError;
use crate::keystone::ServiceState;

/// Credential backend driver interface (ADR 0019).
///
/// The backend owns the Fernet encryption/decryption of `blob` and the
/// `key_hash` bookkeeping; every method here deals in plaintext `blob`
/// values only. The backing `credential` table is owned and schema-managed
/// exclusively by the Python Keystone service via `alembic` — no
/// implementation of this trait may issue DDL against it.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait CredentialBackend: Send + Sync {
    /// Create a new credential.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `rec`: The credential creation request (`user_id` must already be
    ///   resolved by the caller — see ADR 0019 §2 for the system-scope rule).
    ///
    /// # Returns
    /// - `Result<Credential, CredentialProviderError>` - The created credential
    ///   (decrypted `blob`) or an error.
    async fn create_credential(
        &self,
        state: &ServiceState,
        rec: CredentialCreate,
    ) -> Result<Credential, CredentialProviderError>;

    /// Get a single credential by ID.
    async fn get_credential<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Credential>, CredentialProviderError>;

    /// Look up a credential by the plaintext EC2 access key
    /// (`id == SHA-256(access)`). Used by the OS-EC2 legacy endpoints and by
    /// `/v3/ec2tokens` (ADR 0019 §3, §5).
    async fn get_credential_by_ec2_access<'a>(
        &self,
        state: &ServiceState,
        access: &'a str,
    ) -> Result<Option<Credential>, CredentialProviderError>;

    /// List credentials matching the given driver-level hints
    /// (`user_id`/`type`). Callers are responsible for the second policy
    /// enforcement pass described in ADR 0019 §2 (CVE-2019-19687).
    async fn list_credentials(
        &self,
        state: &ServiceState,
        params: &CredentialListParameters,
    ) -> Result<Vec<Credential>, CredentialProviderError>;

    /// List all credentials owned by a user, optionally filtered by type.
    /// Used by the TOTP/MFA auth pipeline (`type = "totp"`) and by the
    /// OS-EC2 listing endpoint (`type = "ec2"`).
    async fn list_credentials_for_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        r#type: Option<&'a str>,
    ) -> Result<Vec<Credential>, CredentialProviderError>;

    /// Update a credential. Updating `blob` triggers re-encryption with the
    /// current Primary Key and updates `key_hash`.
    async fn update_credential<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        rec: CredentialUpdate,
    ) -> Result<Credential, CredentialProviderError>;

    /// Delete a credential by ID.
    async fn delete_credential<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), CredentialProviderError>;

    /// Delete all credentials owned by a user (identity lifecycle cascade).
    async fn delete_credentials_for_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), CredentialProviderError>;

    /// Delete all credentials bound to a project (identity lifecycle
    /// cascade; primarily EC2 credentials).
    async fn delete_credentials_for_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<(), CredentialProviderError>;
}
