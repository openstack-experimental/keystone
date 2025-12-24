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
//! Trust provider: database backend driver.

use async_trait::async_trait;

use super::TrustBackend;
use crate::config::Config;
use crate::keystone::ServiceState;
use crate::trust::{TrustError, types::*};

mod trust;

/// Sql Database revocation backend.
#[derive(Clone, Debug, Default)]
pub struct SqlBackend {
    pub config: Config,
}

impl SqlBackend {}

#[async_trait]
impl TrustBackend for SqlBackend {
    /// Set config.
    fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// Get trust by ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_trust<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Trust>, TrustError> {
        Ok(trust::get(&state.db, id).await?)
    }

    /// List trusts.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_trusts(
        &self,
        state: &ServiceState,
        params: &TrustListParameters,
    ) -> Result<Vec<Trust>, TrustError> {
        Ok(trust::list(&state.db, params).await?)
    }
}

#[cfg(test)]
mod tests {}
