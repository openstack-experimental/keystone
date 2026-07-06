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
//! # SCIM resource ownership index provider (ADR 0024 §3.A)
//!
//! Tracks which realm (`provider_id`) owns each SCIM-provisioned `User`/
//! `Group`, backing the Ownership Fencing Algorithm (§3.C).

pub mod backend;
pub mod error;
mod provider_api;
pub mod service;

#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockScimResourceProvider;
pub use error::ScimResourceProviderError;
pub use provider_api::ScimResourceApi;
pub use service::ScimResourceService;
