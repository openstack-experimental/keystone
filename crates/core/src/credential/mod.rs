// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! # Credentials provider (ADR 0019)
//!
//! Blind storage for sensitive authentication secrets (EC2 access/secret
//! keys, TOTP seeds, and arbitrary third-party blobs), encrypted at rest
//! with Fernet using a key repository separate from `[fernet_tokens]`. The
//! `credential` table is owned and schema-managed exclusively by the Python
//! Keystone service via `alembic`; Keystone-NG treats it as read/write but
//! never issues DDL against it, and all encryption/hashing behaviour is
//! byte-for-byte compatible with Python Keystone so blobs written by either
//! service can be decrypted by the other.

pub mod backend;
pub mod ec2_signature;
pub mod error;
pub mod hook;
mod provider_api;
pub mod service;

pub use error::CredentialProviderError;
pub use hook::CredentialHook;
pub use provider_api::CredentialApi;
pub use service::CredentialService;

#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockCredentialProvider;
