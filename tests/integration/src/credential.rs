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
//! Integration tests for the credentials provider (ADR 0019).
//!
//! Unlike every other entity exercised in this test suite, the `credential`
//! table is owned exclusively by Python Keystone's `alembic` migrations
//! (ADR 0019 §1): `SqlDriver::setup()` for the credential backend is a
//! deliberate no-op. `common::setup_schema()` creates the table separately
//! via the crate's `test_support` helper (test-only, never used in
//! production) so it is present for every integration test, matching real
//! deployments where the table always pre-exists. [`get_state`] below layers
//! on top of `common::get_state()` only to initialize a throwaway Fernet key
//! repository, which is specific to credential encrypt/decrypt tests.

use std::fs::create_dir;
use std::pin::Pin;
use std::sync::Arc;

use eyre::Result;
use tempfile::TempDir;

use openstack_keystone::keystone::Service;
use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::credential::*;
use openstack_keystone_credential_driver_sql::fernet::FernetKeyRepository;

use crate::common::*;
use crate::impl_deleter;

mod create;
mod delete;
mod get;
mod list;
mod update;

impl_deleter!(
    Service,
    Credential,
    get_credential_provider,
    delete_credential
);

/// Build a [`ServiceState`] with a working Fernet key repository — the
/// `credential` table itself is created generically by
/// `common::setup_schema()` for every integration test (see module docs).
pub async fn get_state() -> Result<(ServiceState, TempDir)> {
    let (state, tmp_dir) = crate::common::get_state().await?;

    let key_repository = tmp_dir.path().join("credential-keys");
    create_dir(&key_repository)?;
    FernetKeyRepository::new(key_repository.clone())
        .setup()
        .await?;

    {
        let mut cfg = state.config_manager.config.write().await;
        cfg.credential.key_repository = key_repository;
    }

    Ok((state, tmp_dir))
}

pub async fn create_credential(
    state: &ServiceState,
    data: CredentialCreate,
) -> Result<AsyncResourceGuard<Credential, ServiceState>> {
    let res = state
        .provider
        .get_credential_provider()
        .create_credential(&ExecutionContext::internal(state), data)
        .await?;
    Ok(AsyncResourceGuard::new(res, state.clone()))
}
