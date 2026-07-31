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
//! Raft-backed OAuth2 client registration CRUD (`oauth2-client-driver-raft`,
//! ADR 0026 §5) plus the read-heavy jwks/well-known discovery endpoints,
//! which are the actual steady-state traffic most OAuth2 consumers generate.

use goose::prelude::*;
use serde_json::json;
use uuid::Uuid;

use crate::Session;

const DEFAULT_DOMAIN_ID: &str = "default";

/// GET jwks for the `default` domain (read-heavy, exercises linearizable
/// reads against `oauth2-key-driver-raft`).
pub async fn jwks(user: &mut GooseUser) -> TransactionResult {
    let path = format!("/v4/oauth2/{DEFAULT_DOMAIN_ID}/jwks");
    let req = user.get_request_builder(&GooseMethod::Get, &path)?;

    let goose_request = GooseRequest::builder()
        .name("GET /v4/oauth2/:domain_id/jwks")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// GET well-known OIDC discovery document for the `default` domain.
pub async fn well_known(user: &mut GooseUser) -> TransactionResult {
    let path = format!("/v4/oauth2/{DEFAULT_DOMAIN_ID}/.well-known/openid-configuration");
    let req = user.get_request_builder(&GooseMethod::Get, &path)?;

    let goose_request = GooseRequest::builder()
        .name("GET /v4/oauth2/:domain_id/.well-known/openid-configuration")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// List registered OAuth2 clients for the `default` domain.
pub async fn list_clients(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let path = format!("/v4/oauth2/{DEFAULT_DOMAIN_ID}/clients");
    let req = user
        .get_request_builder(&GooseMethod::Get, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("GET /v4/oauth2/:domain_id/clients")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// Register an OAuth2 client owned by this virtual user (on_start for
/// OAuth2ClientCRUD).
pub async fn create_client(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let provider_id = format!("loadtest-client-{}", Uuid::new_v4().as_simple());
    let body = json!({
        "oauth2_client": {
            "confidential": true,
            "grant_types": ["client_credentials"],
            "provider_id": provider_id,
            "token_endpoint_auth_method": "client_secret_basic"
        }
    });

    let path = format!("/v4/oauth2/{DEFAULT_DOMAIN_ID}/clients");
    let req = user
        .get_request_builder(&GooseMethod::Post, &path)?
        .header("x-auth-token", &token)
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("POST /v4/oauth2/:domain_id/clients (setup)")
        .set_request_builder(req)
        .build();

    let mut goose = user.request(goose_request).await?;
    let response = match goose.response {
        Ok(r) => r,
        Err(e) => {
            return user.set_failure(
                &format!("oauth2 client create failed: {e}"),
                &mut goose.request,
                None,
                None,
            );
        }
    };

    if !response.status().is_success() {
        return user.set_failure(
            &format!("oauth2 client create returned {}", response.status()),
            &mut goose.request,
            None,
            None,
        );
    }

    let session = user.get_session_data_unchecked_mut::<Session>();
    session.oauth2_client_id = Some(provider_id);

    Ok(())
}

/// Show the OAuth2 client owned by this virtual user.
pub async fn show_client(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();
    let client_id = match &session.oauth2_client_id {
        Some(id) => id.clone(),
        None => return Ok(()),
    };

    let path = format!("/v4/oauth2/{DEFAULT_DOMAIN_ID}/clients/{client_id}");
    let req = user
        .get_request_builder(&GooseMethod::Get, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("GET /v4/oauth2/:domain_id/clients/:provider_id")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// Delete the OAuth2 client owned by this virtual user (on_stop for
/// OAuth2ClientCRUD).
pub async fn delete_client(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();
    let client_id = match &session.oauth2_client_id {
        Some(id) => id.clone(),
        None => return Ok(()),
    };

    let path = format!("/v4/oauth2/{DEFAULT_DOMAIN_ID}/clients/{client_id}");
    let req = user
        .get_request_builder(&GooseMethod::Delete, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("DELETE /v4/oauth2/:domain_id/clients/:provider_id (teardown)")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;

    let session = user.get_session_data_unchecked_mut::<Session>();
    session.oauth2_client_id = None;

    Ok(())
}
