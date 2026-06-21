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
//! # Federation provider
//!
//! Federation provider implements the functionality necessary for the user
//! federation.

pub mod backend;
pub mod error;
pub mod hook;
#[cfg(any(test, feature = "mock"))]
pub mod mock;
mod provider_api;
pub mod service;

pub use crate::federation::error::FederationProviderError;
pub use hook::FederationHook;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockFederationProvider;
pub use provider_api::FederationApi;
pub use service::FederationService;
