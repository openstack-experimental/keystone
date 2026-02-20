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
use crate::keystone::ServiceState;
use crate::trust::{TrustProviderError, types::*};

pub(crate) mod trust;

/// Sql Database revocation backend.
#[derive(Default)]
pub struct SqlBackend {}

#[async_trait]
impl TrustBackend for SqlBackend {
    /// Get trust by ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_trust<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Trust>, TrustProviderError> {
        Ok(trust::get(&state.db, id).await?)
    }

    /// Resolve trust chain by the trust ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_trust_delegation_chain<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Vec<Trust>>, TrustProviderError> {
        Ok(trust::get_delegation_chain(&state.db, id).await?)
    }

    /// List trusts.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_trusts(
        &self,
        state: &ServiceState,
        params: &TrustListParameters,
    ) -> Result<Vec<Trust>, TrustProviderError> {
        Ok(trust::list(&state.db, params).await?)
    }
}

impl From<crate::error::DatabaseError> for TrustProviderError {
    fn from(source: crate::error::DatabaseError) -> Self {
        match source {
            cfl @ crate::error::DatabaseError::Conflict { .. } => Self::Conflict(cfl.to_string()),
            other => Self::Driver(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {}
