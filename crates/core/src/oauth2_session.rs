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
//! # OAuth2 browser session provider (ADR 0026 §10 Phase 4)
//!
//! Internal plumbing consumed directly by the `/authorize` and `/token`
//! handlers -- not an admin-facing CRUD resource, so (like
//! [`crate::oauth2_key`]) this provider takes `&ServiceState` directly
//! rather than routing through [`crate::auth::ExecutionContext`]'s policy
//! layer.

pub mod backend;
pub mod error;
pub mod provider_api;
pub mod service;

#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockOauth2SessionProvider;
pub use error::Oauth2SessionProviderError;
pub use provider_api::{
    IssueAuthorizationCodeRequest, IssueRefreshTokenRequest, Oauth2SessionApi,
    RefreshTokenRedemption, StartPreAuthSessionRequest,
};
pub use service::Oauth2SessionService;
