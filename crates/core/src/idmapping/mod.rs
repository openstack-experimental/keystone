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

//! # IdMapping provider
//!
//! IdMapping provider provides a mapping of the entity ID between
//! Keystone and the remote system (i.e. LDAP, IdP, OpenFGA, SCIM, etc).

pub mod backend;
pub mod error;
pub mod hook;
mod provider_api;
pub mod service;

pub use error::IdMappingProviderError;
pub use hook::IdMappingHook;
pub use provider_api::IdMappingApi;
pub use service::IdMappingService;

#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockIdMappingProvider;
