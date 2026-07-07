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
//! `GET /SCIM/v2/{domain_id}/{ServiceProviderConfig,Schemas,ResourceTypes}`
//! (ADR 0024 §5.A tail) — static discovery documents. Unauthenticated within
//! the SCIM sub-router: these describe the protocol surface only, carry no
//! tenant data, and RFC 7644 clients probe them before presenting
//! credentials, so gating them behind `ScimRealmAuth` would break discovery
//! for exactly the clients that need it. Honestly advertises
//! `bulk.supported: false`, `sort.supported: false`, and the restricted
//! filter grammar (§5.B) rather than claiming full RFC 7644 compliance.

use axum::{Json, Router, routing::get};
use serde_json::{Value, json};

use openstack_keystone_core::keystone::ServiceState;

async fn service_provider_config() -> Json<Value> {
    Json(json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": true },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "API Key",
            "description": "Realm-scoped API key bearer token (ADR 0021)",
            "primary": true
        }]
    }))
}

async fn schemas() -> Json<Value> {
    Json(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
        "Resources": [
            {
                "id": "urn:ietf:params:scim:schemas:core:2.0:User",
                "name": "User",
                "description": "ADR 0024 pragmatic subset of the RFC 7644 User resource",
            },
            {
                "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
                "name": "Group",
                "description": "ADR 0024 pragmatic subset of the RFC 7644 Group resource",
            },
        ]
    }))
}

async fn resource_types() -> Json<Value> {
    Json(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
        "Resources": [
            {
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
            },
            {
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
            },
        ]
    }))
}

/// SCIM discovery sub-router, nested at `/SCIM/v2/{domain_id}`.
pub fn router() -> Router<ServiceState> {
    Router::new()
        .route("/ServiceProviderConfig", get(service_provider_config))
        .route("/Schemas", get(schemas))
        .route("/ResourceTypes", get(resource_types))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_provider_config_advertises_no_bulk_or_sort() {
        let Json(body) = service_provider_config().await;
        assert_eq!(body["bulk"]["supported"], false);
        assert_eq!(body["sort"]["supported"], false);
        assert_eq!(body["patch"]["supported"], true);
    }

    #[tokio::test]
    async fn test_schemas_lists_user_and_group() {
        let Json(body) = schemas().await;
        assert_eq!(body["totalResults"], 2);
    }

    #[tokio::test]
    async fn test_resource_types_lists_user_and_group_endpoints() {
        let Json(body) = resource_types().await;
        let endpoints: Vec<&str> = body["Resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["endpoint"].as_str().unwrap())
            .collect();
        assert_eq!(endpoints, vec!["/Users", "/Groups"]);
    }
}
