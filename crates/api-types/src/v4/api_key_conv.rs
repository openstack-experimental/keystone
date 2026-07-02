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
//! API Key (SCIM ingress) type conversions (ADR 0021).
//!
//! `ApiClientResourceCreate` is deliberately not built here: `client_id`,
//! `lookup_hash`, and `secret_hash` are derived from freshly generated token
//! entropy on the authentication-adjacent hot path (`crates/core/src/api_key`),
//! not from the wire request, so that assembly stays in the HTTP handler
//! rather than a pure structural conversion.

use chrono::DateTime;

use openstack_keystone_core_types::api_key as core;

use crate::v4::api_key as api;

impl From<core::ApiClientResource> for api::ApiKey {
    fn from(value: core::ApiClientResource) -> Self {
        Self {
            allowed_ips: value.allowed_ips,
            client_id: value.client_id,
            created_at: DateTime::from_timestamp(value.created_at, 0).unwrap_or_default(),
            description: value.description,
            domain_id: value.domain_id,
            enabled: value.enabled,
            expires_at: DateTime::from_timestamp(value.expires_at, 0).unwrap_or_default(),
            last_used_at: value
                .last_used_at
                .and_then(|ts| DateTime::from_timestamp(ts, 0)),
            provider_id: value.provider_id,
            revoked_at: value
                .revoked_at
                .and_then(|ts| DateTime::from_timestamp(ts, 0)),
            revoked_by: value.revoked_by,
        }
    }
}

impl From<api::ApiKeyUpdate> for core::ApiClientResourceUpdate {
    fn from(value: api::ApiKeyUpdate) -> Self {
        Self {
            allowed_ips: value.allowed_ips,
            description: value.description,
            enabled: value.enabled,
        }
    }
}

impl From<api::ApiKeyListParameters> for core::ApiClientResourceListParameters {
    fn from(value: api::ApiKeyListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            provider_id: value.provider_id,
            enabled: value.enabled,
        }
    }
}
