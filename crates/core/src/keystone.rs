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
use openstack_keystone_distributed_storage::StorageApi;
use sea_orm::DatabaseConnection;
use std::sync::Arc;
use tracing::info;

use openstack_keystone_config::Config;
use openstack_keystone_distributed_storage::app::{Storage, init_storage};

use crate::error::KeystoneError;
use crate::policy::PolicyEnforcer;
use crate::provider::Provider;

// Placing ServiceState behind Arc is necessary to address DatabaseConnection
// not implementing Clone.
//#[derive(Clone)]
pub struct Service {
    /// Config file.
    pub config: Config,

    /// Database connection.
    pub db: DatabaseConnection,

    /// Policy enforcer.
    pub policy_enforcer: Arc<dyn PolicyEnforcer>,

    /// Service/resource Provider.
    pub provider: Provider,

    /// Distributed storage.
    pub storage: Option<Storage>,

    /// Shutdown flag.
    pub shutdown: bool,
}

pub type ServiceState = Arc<Service>;

impl Service {
    /// Creates a new Keystone service instance.
    ///
    /// # Parameters
    /// - `cfg`: The configuration for the service.
    /// - `db`: The database connection.
    /// - `provider`: The provider for services/resources.
    /// - `policy_enforcer`: The policy enforcer instance.
    ///
    /// # Returns
    /// - `Ok(Self)` if the service was initialized successfully.
    /// - `Err(KeystoneError)` if there was an error during initialization.
    pub async fn new(
        cfg: Config,
        db: DatabaseConnection,
        provider: Provider,
        policy_enforcer: Arc<dyn PolicyEnforcer>,
    ) -> Result<Self, KeystoneError> {
        let storage = if let Some(ds) = &cfg.distributed_storage {
            // Initialize the raft backed storage.
            Some(
                init_storage(ds)
                    .await
                    .map_err(|e| KeystoneError::Provider {
                        source: Box::new(e),
                    })?,
            )
        } else {
            None
        };

        Ok(Self {
            config: cfg.clone(),
            provider,
            db,
            policy_enforcer,
            storage,
            shutdown: false,
        })
    }

    /// Returns a reference to the distributed storage if available.
    ///
    /// # Returns
    /// - `Some(&impl StorageApi)` if storage is configured, otherwise `None`.
    pub fn get_storage(&self) -> Option<&impl StorageApi> {
        self.storage.as_ref()
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
