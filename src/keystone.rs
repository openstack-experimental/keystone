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

use axum::extract::{FromRef, FromRequestParts};
use mockall_double::double;
use sea_orm::DatabaseConnection;
use std::sync::Arc;
use tracing::info;
use webauthn_rs::{Webauthn, WebauthnBuilder, prelude::Url};

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
    /// Config file
    pub config: Config,
    /// Service/resource Provider
    pub provider: Provider,
    /// Database connection
    #[from_ref(skip)]
    pub db: DatabaseConnection,

    /// Policy factory
    pub policy_factory: Arc<PolicyFactory>,

    /// WebAuthN provider
    pub webauthn: Webauthn,

    /// Shutdown flag
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
        // Effective domain name.
        let rp_id = "localhost";
        // Url containing the effective domain name
        // TODO: This must come from the configuration file.
        // MUST include the port number!
        let rp_origin = Url::parse("http://localhost:8080")?;
        let builder = WebauthnBuilder::new(rp_id, &rp_origin)?;

        // Now, with the builder you can define other options.
        // Set a "nice" relying party name. Has no security properties and
        // may be changed in the future.
        let builder = builder.rp_name("Keystone");

        // Consume the builder and create our webauthn instance.
        let webauthn = builder.build()?;

        Ok(Self {
            config: cfg.clone(),
            provider,
            db,
            policy_factory: Arc::new(policy_factory),
            webauthn,
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
