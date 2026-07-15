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
//! # OAuth2 client (relying party registration) provider (ADR 0026 §5, Phase 2)
//!
//! Admin CRUD for `OAuth2Client` registrations: storage schema and
//! validation only in Phase 2 -- wiring into the mapping engine's
//! `IdentitySource` for actual `/token` issuance is Phase 3/4.

pub mod backend;
pub mod crypto;
pub mod error;
pub mod pkce;
mod provider_api;
pub mod service;
pub mod token;
pub mod verify;

#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockOauth2ClientProvider;
pub use error::Oauth2ClientProviderError;
pub use provider_api::Oauth2ClientApi;
pub use service::Oauth2ClientService;
pub use token::{build_access_token_claims, hydrate_client_credentials_context};
pub use verify::{TokenVerificationError, verify_openstack_access_token};
