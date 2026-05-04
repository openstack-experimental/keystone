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
//! Token revocation errors.
pub use openstack_keystone_core_types::revoke::RevokeProviderError;

impl From<crate::error::DatabaseError> for RevokeProviderError {
    /// Convert a DatabaseError to a RevokeProviderError.
    ///
    /// # Arguments
    /// * `source` - The database error to convert.
    fn from(source: crate::error::DatabaseError) -> Self {
        match source {
            cfl @ crate::error::DatabaseError::Conflict { .. } => Self::Conflict(cfl.to_string()),
            other => Self::Driver(other.to_string()),
        }
    }
}
