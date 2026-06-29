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
//! # Keystone state
use std::sync::Arc;

use sea_orm::DatabaseConnection;
use tracing::info;

use openstack_keystone_audit::AuditDispatcher;
use openstack_keystone_config::ConfigManager;
use openstack_keystone_storage_api::StorageApi;

use crate::error::KeystoneError;
use crate::events::EventDispatcher;
use crate::policy::PolicyEnforcer;
use crate::provider::Provider;

// Placing ServiceState behind Arc is necessary to address DatabaseConnection
// not implementing Clone.
//#[derive(Clone)]
pub struct Service {
    /// Config file.
    pub config_manager: Arc<ConfigManager>,

    /// Database connection.
    pub db: DatabaseConnection,

    /// Policy enforcer.
    pub policy_enforcer: Arc<dyn PolicyEnforcer>,

    /// Service/resource Provider.
    pub provider: Provider,

    /// Event dispatcher for inter-provider notifications.
    pub event_dispatcher: Arc<EventDispatcher>,

    /// Audit dispatcher for fail-closed audit records.
    pub audit_dispatcher: Arc<AuditDispatcher>,

    /// Distributed storage instance (when configured).
    pub storage: Option<Arc<dyn StorageApi>>,

    /// Shutdown flag.
    pub shutdown: bool,
}

pub type ServiceState = Arc<Service>;

impl Service {
    /// Creates a new Keystone service instance.
    ///
    /// # Parameters
    /// - `cfg`: The configuration manager for the service.
    /// - `db`: The database connection.
    /// - `provider`: The provider for services/resources.
    /// - `policy_enforcer`: The policy enforcer instance.
    /// - `audit_dispatcher`: The audit dispatcher for fail-closed audit
    ///   records.
    /// - `storage`: Optional distributed storage instance.
    ///
    /// # Returns
    /// - `Ok(Self)` if the service was initialized successfully.
    /// - `Err(KeystoneError)` if there was an error during initialization.
    pub async fn new(
        cfg: Arc<ConfigManager>,
        db: DatabaseConnection,
        provider: Provider,
        policy_enforcer: Arc<dyn PolicyEnforcer>,
        audit_dispatcher: Arc<AuditDispatcher>,
        storage: Option<Arc<dyn StorageApi>>,
    ) -> Result<Self, KeystoneError> {
        Ok(Self {
            config_manager: cfg,
            provider,
            event_dispatcher: EventDispatcher::production(),
            audit_dispatcher,
            db,
            policy_enforcer,
            storage,
            shutdown: false,
        })
    }

    /// Terminates the Keystone service.
    ///
    /// # Returns
    /// - `Ok(())` upon successful termination.
    /// - `Err(KeystoneError)` if an error occurred during termination.
    pub async fn terminate(&self) -> Result<(), KeystoneError> {
        info!("Terminating Keystone");
        Ok(())
    }
}
