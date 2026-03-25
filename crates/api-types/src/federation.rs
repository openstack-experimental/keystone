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
//! # Federation API types
mod auth;
mod identity_provider;
#[cfg(feature = "conv")]
mod identity_provider_conv;
mod mapping;
#[cfg(feature = "conv")]
mod mapping_conv;

pub use auth::*;
pub use identity_provider::*;
pub use mapping::*;

#[cfg(feature = "conv")]
use openstack_keystone_core_types::federation::FederationProviderError;
#[cfg(feature = "conv")]
impl From<FederationProviderError> for crate::error::KeystoneApiError {
    fn from(source: FederationProviderError) -> Self {
        match source {
            FederationProviderError::IdentityProviderNotFound(x) => Self::NotFound {
                resource: "identity provider".into(),
                identifier: x,
            },
            FederationProviderError::MappingNotFound(x) => Self::NotFound {
                resource: "mapping provider".into(),
                identifier: x,
            },
            FederationProviderError::Conflict(x) => Self::Conflict(x),
            other => Self::InternalError(other.to_string()),
        }
    }
}
