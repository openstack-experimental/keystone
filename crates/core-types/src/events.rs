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
//! # Service State Change Events
//!
//! Provides event types for inter-provider and extension communication.
//! When a provider performs a CRUD operation, it emits an [Event] that
//! any other provider or extension can subscribe to.
//!
//! The event system uses a broadcast channel pattern:
//! - One sender (via `EventDispatcher`) in the core service
//! - Multiple receivers (providers and extensions subscribe independently)
//!
//! Events are fire-and-forget: if a subscriber is slow or disconnected,
//! events are silently dropped. This prevents a slow subscriber from blocking
//! the main operation.

use chrono::{DateTime, Utc};

/// Domain event representing a create/update/delete operation on a Keystone
/// entity.
#[derive(Debug, Clone)]
pub struct Event {
    /// When the event was emitted.
    pub timestamp: DateTime<Utc>,
    /// The type of operation.
    pub operation: Operation,
    /// The entity payload (specific to each domain).
    pub payload: EventPayload,
}

/// [`Operation::Other`] value of a user's password change (self-service
/// or administrative), emitted with [`EventPayload::User`].
pub const PASSWORD_CHANGE_OPERATION: &str = "password_change";

/// CRUD operation type.
#[derive(Debug, Clone)]
pub enum Operation {
    Create,
    Update,
    Delete,
    /// Disable an entity (e.g. disable a user or project).
    Disable,
    /// Re-enable a previously disabled entity.
    Enable,
    /// Authenticate — issue or validate a credential.
    Authenticate,
    /// Revoke a token or credential.
    Revoke,
    /// Any other operation not covered by the variants above.
    ///
    /// The inner string is sanitized by `map_event_to_action` before
    /// it reaches the audit record.
    Other(String),
}

/// Entity-specific payload for each domain event.
#[derive(Debug, Clone)]
pub enum EventPayload {
    // Identity
    User {
        id: String,
    },
    Group {
        id: String,
    },
    GroupMembership {
        user_id: String,
        group_ids: Vec<String>,
    },

    // Resources
    Project {
        id: String,
    },
    Domain {
        id: String,
    },

    // Roles and assignments
    Role {
        id: String,
    },
    RoleImply {
        prior_role_id: String,
        implied_role_id: String,
    },
    RoleAssignment {
        role_id: String,
        user_id: Option<String>,
        group_id: Option<String>,
        project_id: Option<String>,
        domain_id: Option<String>,
        system_id: Option<String>,
    },

    // Credentials
    ApplicationCredential {
        id: String,
        project_id: String,
    },
    AccessRule {
        id: String,
        user_id: String,
    },

    // Credentials provider (ADR 0019: EC2/TOTP/custom credential blobs)
    Credential {
        id: String,
        user_id: String,
    },

    // All credentials of a user or of a project, removed together when the
    // owner is deleted. Exactly one of the two IDs is set; no credential
    // IDs or blobs are carried.
    CredentialSet {
        user_id: Option<String>,
        project_id: Option<String>,
    },

    // Catalog
    Endpoint {
        id: String,
    },
    EndpointGroup {
        id: String,
    },
    ProjectEndpoint {
        project_id: String,
        endpoint_id: String,
    },
    ProjectEndpointGroup {
        project_id: String,
        endpoint_group_id: String,
    },
    Region {
        id: String,
    },
    Service {
        id: String,
    },

    // Limits
    Limit {
        id: String,
    },
    RegisteredLimit {
        id: String,
    },

    // Token
    TokenRestriction {
        id: String,
    },

    // Federation
    IdentityProvider {
        id: String,
    },
    AuthState {
        id: String,
    },

    // Mapping
    MappingRuleSet {
        mapping_id: String,
    },
    VirtualUser {
        user_id: String,
    },

    // Kubernetes auth
    K8sAuthInstance {
        id: String,
    },

    // SCIM v2 provisioning (ADR 0024)
    ScimRealm {
        provider_id: String,
    },

    // Trusts
    Trust {
        id: String,
    },

    // Policy blob store (legacy `/v3/policies`)
    //
    // Carries the ID only. The policy `blob` is arbitrary caller-supplied
    // data and `blob` is on the audit denylist enforced by
    // `tools/check_event_payload_no_secret_fields.py`.
    Policy {
        id: String,
    },

    // API keys (ADR 0021). Carries the public `client_id`, never the key
    // material, its lookup hash or its secret hash.
    ApiKey {
        domain_id: String,
        client_id: String,
    },

    // OAuth2 relying-party registrations (ADR 0026 §5). `provider_id` is the
    // registration ID; `client_secret` and its hash are never carried.
    Oauth2Client {
        domain_id: String,
        provider_id: String,
    },

    // Per-domain OAuth2 signing key set (rotation, emergency rotation).
    Oauth2SigningKey {
        domain_id: String,
    },

    // Token revocation (`DELETE /v3/auth/tokens`, revocation events). Both
    // fields are IDs of the revoked subject; at least one is set.
    RevocationEvent {
        audit_id: Option<String>,
        user_id: Option<String>,
    },

    // Domain configuration (ADR 0034). Carries the domain ID only: option
    // values can hold LDAP bind credentials and are never part of the event.
    DomainConfig {
        domain_id: String,
    },

    // Public-ID mappings of non-local identity backends.
    IdMapping {
        domain_id: Option<String>,
        public_id: Option<String>,
    },

    // Dynamic auth plugin identity links (plugin name + external ID -> user).
    PluginIdentity {
        plugin_name: Option<String>,
        user_id: Option<String>,
    },

    // SCIM resource index entries (ADR 0024).
    ScimIndex {
        provider_id: String,
        keystone_id: String,
    },
}

impl Event {
    /// Create a new event with the current timestamp.
    ///
    /// # Parameters
    /// - `operation`: The type of operation.
    /// - `payload`: The entity-specific data.
    ///
    /// # Returns
    /// A new `Event` instance.
    pub fn new(operation: Operation, payload: EventPayload) -> Self {
        Self {
            timestamp: Utc::now(),
            operation,
            payload,
        }
    }
}
