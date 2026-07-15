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
//! OAuth2 client conversion implementations.

use openstack_keystone_core_types::oauth2_client as core;

use crate::v4::oauth2_client as api;

impl From<api::GrantType> for core::GrantType {
    fn from(value: api::GrantType) -> Self {
        match value {
            api::GrantType::AuthorizationCode => Self::AuthorizationCode,
            api::GrantType::ClientCredentials => Self::ClientCredentials,
            api::GrantType::RefreshToken => Self::RefreshToken,
            api::GrantType::DeviceCode => Self::DeviceCode,
            api::GrantType::TokenExchange => Self::TokenExchange,
        }
    }
}

impl From<core::GrantType> for api::GrantType {
    fn from(value: core::GrantType) -> Self {
        match value {
            core::GrantType::AuthorizationCode => Self::AuthorizationCode,
            core::GrantType::ClientCredentials => Self::ClientCredentials,
            core::GrantType::RefreshToken => Self::RefreshToken,
            core::GrantType::DeviceCode => Self::DeviceCode,
            core::GrantType::TokenExchange => Self::TokenExchange,
        }
    }
}

impl From<api::OAuth2ClientCreateRequest> for core::OAuth2ClientResourceCreate {
    /// `domain_id` comes from the URL path (`.domain_id = ...` is set by the
    /// handler after this conversion), not the request body.
    fn from(value: api::OAuth2ClientCreateRequest) -> Self {
        let c = value.oauth2_client;
        Self {
            // Filled in by the service layer (server-generated UUIDv4).
            client_id: String::new(),
            provider_id: c.provider_id,
            // Filled in by the handler from the URL path.
            domain_id: String::new(),
            // Filled in by the service layer after hashing.
            client_secret_hash: None,
            redirect_uris: c.redirect_uris,
            token_endpoint_auth_method: c.token_endpoint_auth_method,
            grant_types: c.grant_types.into_iter().map(Into::into).collect(),
            require_pkce: c.require_pkce,
            allowed_scopes: c.allowed_scopes,
            pre_authorized: c.pre_authorized,
            claims_template: c.claims_template,
        }
    }
}

impl From<api::OAuth2ClientUpdateRequest> for core::OAuth2ClientResourceUpdate {
    fn from(value: api::OAuth2ClientUpdateRequest) -> Self {
        value.oauth2_client.into()
    }
}

impl From<api::OAuth2ClientUpdate> for core::OAuth2ClientResourceUpdate {
    fn from(value: api::OAuth2ClientUpdate) -> Self {
        Self {
            redirect_uris: value.redirect_uris,
            grant_types: value
                .grant_types
                .map(|g| g.into_iter().map(Into::into).collect()),
            require_pkce: value.require_pkce,
            allowed_scopes: value.allowed_scopes,
            pre_authorized: value.pre_authorized,
            enabled: value.enabled,
            claims_template: value.claims_template,
        }
    }
}

impl From<core::OAuth2ClientResource> for api::OAuth2Client {
    fn from(value: core::OAuth2ClientResource) -> Self {
        Self {
            client_id: value.client_id,
            provider_id: value.provider_id,
            domain_id: value.domain_id,
            confidential: value.client_secret_hash.is_some(),
            redirect_uris: value.redirect_uris,
            token_endpoint_auth_method: value.token_endpoint_auth_method,
            grant_types: value.grant_types.into_iter().map(Into::into).collect(),
            require_pkce: value.require_pkce,
            allowed_scopes: value.allowed_scopes,
            pre_authorized: value.pre_authorized,
            enabled: value.enabled,
            claims_template: value.claims_template,
            created_at: value.created_at,
            updated_at: value.updated_at,
            deleted_at: value.deleted_at,
        }
    }
}
