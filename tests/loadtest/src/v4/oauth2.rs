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
//! The token-minting transactions (`client_credentials`, device authorization
//! start) run against the domain created by the seeder, since `default`
//! never gets OAuth2 signing keys.

use std::sync::OnceLock;

use goose::prelude::*;
use serde_json::json;
use uuid::Uuid;

use crate::Session;
use crate::seed::Oauth2Seed;

const DEFAULT_DOMAIN_ID: &str = "default";

static OAUTH2_SEED: OnceLock<Oauth2Seed> = OnceLock::new();

/// Call once before `GooseAttack::execute()` to share the seeded OAuth2
/// domain and clients with all virtual users.
pub fn set_oauth2_seed(seed: Oauth2Seed) {
    OAUTH2_SEED.set(seed).ok();
}

/// Per-VU `client_credentials` client and the resources bound to it.
/// `/token` is rate limited per client, so every virtual user needs its own.
pub struct CcClient {
    pub client_id: String,
    pub secret: String,
    pub provider_id: String,
    pub mapping_id: String,
    /// Admin token for the teardown calls; this struct replaces [`Session`]
    /// in goose's single session-data slot.
    pub token: String,
}

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
            "name": "Load test client",
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

/// Register a `client_credentials` client and bind a mapping ruleset to it in
/// the seeded domain (on_start for OAuth2ClientCredentials).
pub async fn create_cc_client(user: &mut GooseUser) -> TransactionResult {
    let Some(seed) = OAUTH2_SEED.get() else {
        return Ok(());
    };
    let token = user.get_session_data_unchecked::<Session>().token.clone();
    let suffix = Uuid::new_v4().as_simple().to_string();
    let provider_id = format!("loadtest-cc-{suffix}");

    let body = json!({
        "oauth2_client": {
            "provider_id": provider_id,
            "name": "Load test client_credentials",
            "confidential": true,
            "grant_types": ["client_credentials"],
            "allowed_scopes": ["openid"],
            "token_endpoint_auth_method": "client_secret_basic",
            "require_pkce": false,
        }
    });
    let path = format!("/v4/oauth2/{}/clients", seed.domain_id);
    let req = user
        .get_request_builder(&GooseMethod::Post, &path)?
        .header("x-auth-token", &token)
        .json(&body);
    let goose_request = GooseRequest::builder()
        .name("POST /v4/oauth2/:domain_id/clients (cc setup)")
        .set_request_builder(req)
        .build();
    let mut goose = user.request(goose_request).await?;
    let created: serde_json::Value = match goose.response {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or_default(),
        _ => {
            return user.set_failure(
                "oauth2 cc client create failed",
                &mut goose.request,
                None,
                None,
            );
        }
    };
    let (Some(client_id), Some(secret)) = (
        created["oauth2_client"]["client_id"].as_str(),
        created["client_secret"].as_str(),
    ) else {
        return user.set_failure(
            "oauth2 cc client create returned no id/secret",
            &mut goose.request,
            None,
            None,
        );
    };
    let mapping_id = format!("loadtest-oauth2-cc-{suffix}");
    let cc = CcClient {
        client_id: client_id.to_owned(),
        secret: secret.to_owned(),
        provider_id: provider_id.clone(),
        mapping_id: mapping_id.clone(),
        token: token.clone(),
    };

    let body = json!({
        "mapping": {
            "mapping_id": mapping_id,
            "domain_id": seed.domain_id,
            "domain_resolution_mode": {"type": "fixed"},
            "enabled": true,
            "source": {"type": "o_auth2_client", "provider_id": provider_id},
            "rules": [{
                "name": "loadtest-oauth2-cc",
                "match": {"all_of": []},
                "identity": {"user_name": "${claims.oauth2_client.client_id}"},
                "groups": [],
                "authorizations": [{
                    "type": "domain",
                    "domain_id": seed.domain_id,
                    "roles": [{"id": seed.reader_role_id, "name": "reader"}]
                }]
            }]
        }
    });
    let req = user
        .get_request_builder(&GooseMethod::Post, "/v4/mappings/rulesets")?
        .header("x-auth-token", &token)
        .json(&body);
    let goose_request = GooseRequest::builder()
        .name("POST /v4/mappings/rulesets (cc setup)")
        .set_request_builder(req)
        .build();
    let mut goose = user.request(goose_request).await?;
    match goose.response {
        Ok(r) if r.status().is_success() => {}
        _ => {
            return user.set_failure(
                "oauth2 cc ruleset create failed",
                &mut goose.request,
                None,
                None,
            );
        }
    }

    user.set_session_data(CcSession(cc));
    Ok(())
}

/// Wrapper so the per-VU client does not collide with [`Session`] in goose's
/// single session-data slot.
struct CcSession(CcClient);

/// Delete the per-VU client and its ruleset (on_stop for
/// OAuth2ClientCredentials).
pub async fn delete_cc_client(user: &mut GooseUser) -> TransactionResult {
    let Some(seed) = OAUTH2_SEED.get() else {
        return Ok(());
    };
    let Some((token, provider_id, mapping_id)) = user.get_session_data::<CcSession>().map(|s| {
        (
            s.0.token.clone(),
            s.0.provider_id.clone(),
            s.0.mapping_id.clone(),
        )
    }) else {
        return Ok(());
    };

    let path = format!("/v4/mappings/rulesets/{mapping_id}");
    let req = user
        .get_request_builder(&GooseMethod::Delete, &path)?
        .header("x-auth-token", &token);
    let goose_request = GooseRequest::builder()
        .name("DELETE /v4/mappings/rulesets/:mapping_id (cc teardown)")
        .set_request_builder(req)
        .build();
    user.request(goose_request).await?;

    let path = format!("/v4/oauth2/{}/clients/{provider_id}", seed.domain_id);
    let req = user
        .get_request_builder(&GooseMethod::Delete, &path)?
        .header("x-auth-token", &token);
    let goose_request = GooseRequest::builder()
        .name("DELETE /v4/oauth2/:domain_id/clients/:provider_id (cc teardown)")
        .set_request_builder(req)
        .build();
    user.request(goose_request).await?;
    Ok(())
}

/// `client_credentials` token request (Argon2 secret verification, security
/// context resolution through the ruleset, JWT signing). A 429 from the
/// per-client limiter is an expected outcome, not a failure.
pub async fn token_client_credentials(user: &mut GooseUser) -> TransactionResult {
    let Some(seed) = OAUTH2_SEED.get() else {
        return Ok(());
    };
    let Some(cc) = user
        .get_session_data::<CcSession>()
        .map(|s| (s.0.client_id.clone(), s.0.secret.clone()))
    else {
        return Ok(());
    };

    let path = format!("/v4/oauth2/{}/token", seed.domain_id);
    let req = user
        .get_request_builder(&GooseMethod::Post, &path)?
        .basic_auth(&cc.0, Some(&cc.1))
        .form(&[("grant_type", "client_credentials")]);
    let goose_request = GooseRequest::builder()
        .name("POST /v4/oauth2/:domain_id/token (client_credentials)")
        .set_request_builder(req)
        .build();
    let mut goose = user.request(goose_request).await?;
    expect_success_or_429(user, &mut goose, "client_credentials token")
}

/// `POST /device_authorization` against the seeded public `device_code`
/// client. Only the start of the flow: finishing it needs a browser login.
pub async fn device_authorization_start(user: &mut GooseUser) -> TransactionResult {
    let Some(seed) = OAUTH2_SEED.get() else {
        return Ok(());
    };
    let path = format!("/v4/oauth2/{}/device_authorization", seed.domain_id);
    let req = user.get_request_builder(&GooseMethod::Post, &path)?.form(&[
        ("client_id", seed.device_client_id.as_str()),
        ("scope", "openid"),
    ]);
    let goose_request = GooseRequest::builder()
        .name("POST /v4/oauth2/:domain_id/device_authorization")
        .set_request_builder(req)
        .build();
    let mut goose = user.request(goose_request).await?;
    expect_success_or_429(user, &mut goose, "device authorization")
}

/// Fail the transaction on anything but 2xx; a 429 from a rate limiter is the
/// designed response to overload, so it is marked successful (goose would
/// otherwise count every non-2xx as a failure).
fn expect_success_or_429(
    user: &mut GooseUser,
    goose: &mut goose::goose::GooseResponse,
    what: &str,
) -> TransactionResult {
    match &goose.response {
        Ok(r) if r.status().is_success() => Ok(()),
        Ok(r) if r.status() == reqwest::StatusCode::TOO_MANY_REQUESTS => {
            user.set_success(&mut goose.request)
        }
        Ok(r) => {
            let msg = format!("{what} returned {}", r.status());
            user.set_failure(&msg, &mut goose.request, None, None)
        }
        Err(e) => {
            let msg = format!("{what} failed: {e}");
            user.set_failure(&msg, &mut goose.request, None, None)
        }
    }
}
