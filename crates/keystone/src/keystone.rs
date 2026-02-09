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
use axum::extract::{FromRef, FromRequestParts};
use mockall_double::double;
use sea_orm::DatabaseConnection;
use std::sync::Arc;
use tracing::info;

use crate::api::error::KeystoneApiError;
use crate::config::Config;
use crate::error::KeystoneError;
#[double]
use crate::policy::Policy;
#[double]
use crate::policy::PolicyFactory;
use crate::provider::Provider;

// Placing ServiceState behind Arc is necessary to address DatabaseConnection
// not implementing Clone.
//#[derive(Clone)]
#[derive(FromRef)]
pub struct Service {
    /// Config file.
    pub config: Config,

    /// Database connection.
    #[from_ref(skip)]
    pub db: DatabaseConnection,

    /// Policy factory.
    pub policy_factory: Arc<PolicyFactory>,

    /// Service/resource Provider.
    #[from_ref(skip)]
    pub provider: Provider,

    /// Shutdown flag.
    pub shutdown: bool,
}

pub type ServiceState = Arc<Service>;

impl Service {
    pub fn new(
        cfg: Config,
        db: DatabaseConnection,
        provider: Provider,
        policy_factory: PolicyFactory,
    ) -> Result<Self, KeystoneError> {
        Ok(Self {
            config: cfg.clone(),
            provider,
            db,
            policy_factory: Arc::new(policy_factory),
            shutdown: false,
        })
    }

    pub async fn terminate(&self) -> Result<(), KeystoneError> {
        info!("Terminating Keystone");
        Ok(())
    }
}

impl FromRequestParts<ServiceState> for Policy {
    type Rejection = KeystoneApiError;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &ServiceState,
    ) -> Result<Self, Self::Rejection> {
        let policy = state.policy_factory.instantiate().await?;
        Ok(policy)
    }
}
