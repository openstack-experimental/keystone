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
//! Shared RFC 8693 request rules for native and on-behalf-of exchange.

use super::{Oauth2TokenError, TokenForm};

pub(super) const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
pub(super) const KEYSTONE_TOKEN_TYPE: &str = "urn:openstack:params:oauth:token-type:keystone";
const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
const API_SCOPE: &str = "openstack:api";

/// Validate the common exchange envelope after the caller's rate limit.
/// Returns the supported protocol scope, never a role or project selector.
/// Audience is already implemented and validated by requested_audience.
pub(super) fn validate_exchange_request(form: &TokenForm) -> Result<String, Oauth2TokenError> {
    let Some(subject_type) = form.subject_token_type.as_deref() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: subject_token_type",
        ));
    };
    match subject_type {
        ACCESS_TOKEN_TYPE | KEYSTONE_TOKEN_TYPE => {}
        JWT_TOKEN_TYPE => {
            // #1018 extension point: external JWT ingress must use the mapping
            // engine. For compatibility this arm currently permits only JWTs
            // accepted by the existing Keystone-native validation backend.
        }
        _ => {
            return Err(Oauth2TokenError::invalid_request(format!(
                "subject_token_type `{subject_type}` is not supported"
            )));
        }
    }
    if let Some(requested) = form.requested_token_type.as_deref()
        && requested != ACCESS_TOKEN_TYPE
    {
        return Err(Oauth2TokenError::invalid_request(format!(
            "requested_token_type `{requested}` is not supported"
        )));
    }
    if form.actor_token.is_some() || form.actor_token_type.is_some() {
        return Err(Oauth2TokenError::invalid_request(
            "actor_token and actor_token_type are not supported",
        ));
    }
    if !form.resource.is_empty() {
        return Err(Oauth2TokenError::invalid_target(
            "resource is not supported; use audience to request a service type",
        ));
    }
    // Existing exchange claims always carry OpenStack authorization. Until a
    // narrower scope can be enforced, reject every other scope rather than
    // returning a token with more authority than the request describes.
    match form.scope.as_deref() {
        None | Some(API_SCOPE) => Ok(API_SCOPE.to_string()),
        Some(_) => Err(Oauth2TokenError::invalid_scope(
            "token exchange supports only the openstack:api scope",
        )),
    }
}
