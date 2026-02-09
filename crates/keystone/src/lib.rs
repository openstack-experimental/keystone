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

//! # OpenStack Keystone in Rust
//!
//! The legacy Keystone identity service (written in Python and maintained
//! upstream by OpenStack Foundation) has served the OpenStack ecosystem
//! reliably for years. It handles authentication, authorization, token
//! issuance, service catalog, project/tenant management, and federation
//! services across thousands of deployments. However, as we embarked on adding
//! next-generation identity features—such as native WebAuthn (“passkeys”),
//! modern federation flows, direct OIDC support, JWT login, workload
//! authorization, restricted tokens and service-accounts—it became clear that
//! certain design and performance limitations of the Python codebase would
//! hamper efficient implementation of these new features.
//!
//! Consequently, we initiated a project termed “Keystone-NG”: a Rust-based
//! component that augments rather than fully replaces the existing Keystone
//! service. The original plan was to implement only the new feature-set in Rust
//! and route those new API paths to the Rust component, while keeping the core
//! Python Keystone service in place for existing users and workflows.
//!
//! As development progressed, however, the breadth of new functionality (and
//! the opportunity to revisit some of the existing limitations) led to a
//! partial re-implementation of certain core identity flows in Rust. This
//! allows us to benefit from Rust's memory safety, concurrency model,
//! performance, and modern tooling, while still preserving the upstream
//! Keystone Python service as the canonical “master” identity service, routing
//! only the new endpoints and capabilities through the Rust component.
//!
//! In practice, this architecture means:
//!
//! - The upstream Python Keystone remains the main identity interface,
//!   preserving backward compatibility, integration with other OpenStack
//!   services, existing user workflows, catalogs, policies and plugins.
//!
//! - The Rust “Keystone-NG” component handles new functionality, specifically:
//!
//!   - Native WebAuthN (passkeys) support for passwordless / phishing-resistant
//!     MFA
//!
//!   - A reworked federation service, enabling modern identity brokering and
//!     advanced federation semantics OIDC (OpenID Connect) Direct in Keystone,
//!     enabling Keystone to act as an OIDC Provider or integrate with external
//!     OIDC identity providers natively JWT login flows, enabling stateless,
//!     compact tokens suitable for new micro-services, CLI, SDK, and
//!     workload-to-workload scenarios
//!
//!   - Workload Authorization, designed for service-to-service authorization in
//!     cloud native contexts (not just human users)
//!
//!   - Restricted Tokens and Service Accounts, which allow fine-grained,
//!     limited‐scope credentials for automation, agents, and service accounts,
//!     with explicit constraints and expiry
//!
//! By routing only the new flows through the Rust component we preserve the
//! stability and ecosystem compatibility of Keystone, while enabling a
//! forward-looking identity architecture. Over time, additional identity flows
//! may be migrated or refactored into the Rust component as needed, but our
//! current objective is to retain the existing Keystone Python implementation
//! as the trusted, mature baseline and incrementally build the “Keystone-NG”
//! Rust service as the complement.

pub mod api;
pub mod application_credential;
pub mod assignment;
pub mod auth;
pub mod catalog;
pub mod common;
pub mod config;
pub mod db;
pub mod db_migration;
pub mod error;
pub mod federation;
pub mod identity;
pub mod identity_mapping;
pub mod keystone;
pub mod plugin_manager;
pub mod policy;
pub mod provider;
pub mod resource;
pub mod revoke;
pub mod token;
pub mod trust;
pub mod webauthn;

#[cfg(test)]
mod tests;
