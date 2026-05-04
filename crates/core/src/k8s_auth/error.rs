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
//! # K8s Auth error
pub use openstack_keystone_core_types::k8s_auth::K8sAuthProviderError;

//impl From<jsonwebtoken::errors::Error> for K8sAuthProviderError {
//    fn from(value: jsonwebtoken::errors::Error) -> Self {
//        Self::Jwt {
//            source: Box::new(value),
//        }
//    }
//}
//
//impl From<IdentityProviderError> for K8sAuthProviderError {
//    fn from(value: IdentityProviderError) -> Self {
//        Self::IdentityProvider {
//            source: Box::new(value),
//        }
//    }
//}
//
//impl From<reqwest::Error> for K8sAuthProviderError {
//    fn from(value: reqwest::Error) -> Self {
//        Self::Http {
//            source: Box::new(value),
//        }
//    }
//}

impl From<crate::error::DatabaseError> for K8sAuthProviderError {
    /// Convert a database error into a K8s auth provider error.
    ///
    /// # Arguments
    /// * `source` - The database error to convert.
    ///
    /// # Returns
    /// * Success with the converted `K8sAuthProviderError`.
    fn from(source: crate::error::DatabaseError) -> Self {
        match source {
            cfl @ crate::error::DatabaseError::Conflict { .. } => Self::Conflict(cfl.to_string()),
            other => Self::Driver {
                source: other.into(),
            },
        }
    }
}
