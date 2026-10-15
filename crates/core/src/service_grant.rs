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
//! # Service grant provider (ADR 0036 §4)
//!
//! A user's standing, revocable delegation of a bounded role set on one
//! project to one registered delegatable service (an OAuth2 client with
//! `delegation.service_grants`, ADR 0036 §3).

pub mod backend;
pub mod error;
mod provider_api;
pub mod service;

#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockServiceGrantProvider;
pub use error::ServiceGrantProviderError;
pub use provider_api::ServiceGrantApi;
pub use service::ServiceGrantService;
