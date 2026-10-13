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
//! Live-server OAuth2 client CRUD (`/v4/oauth2/{domain}/clients`,
//! ADR 0026 §5): create / list / show / update / delete / rotate-secret,
//! each with allow, policy-deny and unauthenticated cases.

use eyre::{Result, eyre};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::common::TestClient;
use test_api::oauth2::post_token_form;
use test_api::oauth2_browser::*;

fn url(domain_id: &str, tail: &str) -> Result<url::Url> {
    let base: url::Url = std::env::var("KEYSTONE_URL")?.parse()?;
    Ok(base.join(&format!("v4/oauth2/{domain_id}/clients{tail}"))?)
}

fn body(provider_id: &str) -> Value {
    json!({"oauth2_client": {
        "provider_id": provider_id,
        "name": "crud test client",
        "confidential": true,
        "grant_types": ["client_credentials"],
        "allowed_scopes": ["openid"],
        "token_endpoint_auth_method": "client_secret_basic",
        "require_pkce": false,
    }})
}

fn pid() -> String {
    format!("crud-{}", Uuid::new_v4().simple())
}

/// An authenticated request builder for `token` (`None` = anonymous).
fn authed(rb: RequestBuilder, token: Option<&str>) -> RequestBuilder {
    match token {
        Some(t) => rb.header("x-auth-token", t),
        None => rb,
    }
}

struct Actors {
    domain_id: String,
    other_domain_id: String,
    admin: String,
    manager: String,
    plain: String,
}

async fn actors() -> Result<Actors> {
    let domain_id = create_ready_domain("clients").await?;
    let other_domain_id = create_ready_domain("clients-other").await?;
    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;
    let admin_token = {
        use secrecy::ExposeSecret;
        admin
            .token
            .as_ref()
            .ok_or_else(|| eyre!("admin has no token"))?
            .expose_secret()
            .to_string()
    };

    let manager = project_role_token(&domain_id, "manager").await?;

    let (_id, plain_name) = create_browser_user(&domain_id).await?;
    let plain = user_token(&domain_id, &plain_name, PASSWORD, None).await?;

    Ok(Actors {
        domain_id,
        other_domain_id,
        admin: admin_token,
        manager,
        plain,
    })
}

async fn create(
    a: &Actors,
    domain: &str,
    token: Option<&str>,
    provider_id: &str,
) -> Result<(StatusCode, Value)> {
    let _ = a;
    let rsp = authed(Client::new().post(url(domain, "")?), token)
        .json(&body(provider_id))
        .send()
        .await?;
    let status = rsp.status();
    Ok((status, rsp.json().await.unwrap_or(Value::Null)))
}

// ---- create ----------------------------------------------------------------

#[tokio::test]
#[traced_test]
async fn test_client_create_admin_allowed() -> Result<()> {
    let a = actors().await?;
    let (status, rsp) = create(&a, &a.domain_id, Some(&a.admin), &pid()).await?;
    assert_eq!(status, StatusCode::CREATED, "{rsp}");
    assert!(rsp["client_secret"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(rsp["oauth2_client"]["client_id"].as_str().is_some());
    // The secret is only ever shown once, never as a hash.
    assert!(rsp["oauth2_client"].get("client_secret_hash").is_none());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_create_denied_for_plain_user_and_project_manager() -> Result<()> {
    let a = actors().await?;
    let (status, _) = create(&a, &a.domain_id, Some(&a.plain), &pid()).await?;
    assert!(
        matches!(status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED),
        "{status}"
    );
    // A project-scoped `manager` holds no domain scope (only `admin` can),
    // so policy refuses it even in its own domain.
    for domain in [&a.domain_id, &a.other_domain_id] {
        let (status, _) = create(&a, domain, Some(&a.manager), &pid()).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_create_unauthenticated_and_duplicate() -> Result<()> {
    let a = actors().await?;
    let (status, _) = create(&a, &a.domain_id, None, &pid()).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let p = pid();
    let (status, _) = create(&a, &a.domain_id, Some(&a.admin), &p).await?;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = create(&a, &a.domain_id, Some(&a.admin), &p).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_create_pre_authorized_requires_admin() -> Result<()> {
    let a = actors().await?;
    let mut payload = body(&pid());
    payload["oauth2_client"]["pre_authorized"] = json!(true);
    payload["oauth2_client"]["confidential"] = json!(false);
    payload["oauth2_client"]["token_endpoint_auth_method"] = json!("none");
    payload["oauth2_client"]["require_pkce"] = json!(true);
    let rsp = Client::new()
        .post(url(&a.domain_id, "")?)
        .header("x-auth-token", &a.manager)
        .json(&payload)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::FORBIDDEN);

    // `admin` may register one.
    let mut payload = payload;
    payload["oauth2_client"]["provider_id"] = json!(pid());
    let rsp = Client::new()
        .post(url(&a.domain_id, "")?)
        .header("x-auth-token", &a.admin)
        .json(&payload)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::CREATED);
    let created: Value = rsp.json().await?;
    assert_eq!(created["oauth2_client"]["pre_authorized"], true);
    Ok(())
}

// ---- list / show -----------------------------------------------------------

#[tokio::test]
#[traced_test]
async fn test_client_list_and_show() -> Result<()> {
    let a = actors().await?;
    let p = pid();
    create(&a, &a.domain_id, Some(&a.admin), &p).await?;

    let rsp = Client::new()
        .get(url(&a.domain_id, "")?)
        .header("x-auth-token", &a.admin)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::OK);
    let list: Value = rsp.json().await?;
    assert!(
        list["oauth2_clients"]
            .as_array()
            .is_some_and(|l| l.iter().any(|c| c["provider_id"] == p.as_str())),
        "{list}"
    );

    let rsp = Client::new()
        .get(url(&a.domain_id, &format!("/{p}"))?)
        .header("x-auth-token", &a.admin)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::OK);
    let shown: Value = rsp.json().await?;
    assert_eq!(shown["oauth2_client"]["provider_id"], p.as_str());
    assert!(shown["oauth2_client"].get("client_secret_hash").is_none());
    assert!(shown.get("client_secret").is_none());

    // unknown -> 404
    let rsp = Client::new()
        .get(url(&a.domain_id, "/no-such-client")?)
        .header("x-auth-token", &a.admin)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_list_show_denied_and_unauthenticated() -> Result<()> {
    let a = actors().await?;
    let p = pid();
    create(&a, &a.domain_id, Some(&a.admin), &p).await?;
    for (token, expected) in [
        (
            Some(a.plain.as_str()),
            vec![StatusCode::FORBIDDEN, StatusCode::UNAUTHORIZED],
        ),
        (Some(a.manager.as_str()), vec![StatusCode::FORBIDDEN]),
        (None, vec![StatusCode::UNAUTHORIZED]),
    ] {
        for tail in ["".to_string(), format!("/{p}")] {
            let rsp = authed(Client::new().get(url(&a.domain_id, &tail)?), token)
                .send()
                .await?;
            assert!(expected.contains(&rsp.status()), "{tail}: {}", rsp.status());
        }
    }
    Ok(())
}

// ---- update ----------------------------------------------------------------

#[tokio::test]
#[traced_test]
async fn test_client_update_allowed_denied_unauthenticated() -> Result<()> {
    let a = actors().await?;
    let p = pid();
    create(&a, &a.domain_id, Some(&a.admin), &p).await?;
    let upd = json!({"oauth2_client": {"name": "renamed", "enabled": false}});

    let rsp = Client::new()
        .put(url(&a.domain_id, &format!("/{p}"))?)
        .header("x-auth-token", &a.admin)
        .json(&upd)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::OK);
    let out: Value = rsp.json().await?;
    assert_eq!(out["oauth2_client"]["name"], "renamed");
    assert_eq!(out["oauth2_client"]["enabled"], false);

    let rsp = Client::new()
        .put(url(&a.domain_id, &format!("/{p}"))?)
        .header("x-auth-token", &a.plain)
        .json(&upd)
        .send()
        .await?;
    assert!(matches!(
        rsp.status(),
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED
    ));

    let rsp = Client::new()
        .put(url(&a.domain_id, &format!("/{p}"))?)
        .json(&upd)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_update_cannot_enable_pre_authorized_as_manager() -> Result<()> {
    let a = actors().await?;
    let p = pid();
    create(&a, &a.domain_id, Some(&a.admin), &p).await?;
    let rsp = Client::new()
        .put(url(&a.domain_id, &format!("/{p}"))?)
        .header("x-auth-token", &a.manager)
        .json(&json!({"oauth2_client": {"pre_authorized": true}}))
        .send()
        .await?;
    assert!(
        matches!(
            rsp.status(),
            StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY
        ),
        "{}",
        rsp.status()
    );
    Ok(())
}

// ---- delete ----------------------------------------------------------------

#[tokio::test]
#[traced_test]
async fn test_client_delete_allowed_denied_unauthenticated() -> Result<()> {
    let a = actors().await?;
    let p = pid();
    create(&a, &a.domain_id, Some(&a.admin), &p).await?;

    for (token, expected) in [
        (
            Some(a.plain.as_str()),
            vec![StatusCode::FORBIDDEN, StatusCode::UNAUTHORIZED],
        ),
        (Some(a.manager.as_str()), vec![StatusCode::FORBIDDEN]),
        (None, vec![StatusCode::UNAUTHORIZED]),
    ] {
        let rsp = authed(
            Client::new().delete(url(&a.domain_id, &format!("/{p}"))?),
            token,
        )
        .send()
        .await?;
        assert!(expected.contains(&rsp.status()), "{}", rsp.status());
    }

    let rsp = Client::new()
        .delete(url(&a.domain_id, &format!("/{p}"))?)
        .header("x-auth-token", &a.admin)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::NO_CONTENT);

    let rsp = Client::new()
        .get(url(&a.domain_id, &format!("/{p}"))?)
        .header("x-auth-token", &a.admin)
        .send()
        .await?;
    // Delete is a soft-delete: the registration stays visible, marked revoked.
    assert_eq!(rsp.status(), StatusCode::OK);
    let body: serde_json::Value = rsp.json().await?;
    assert!(
        body["oauth2_client"]["deleted_at"].is_i64(),
        "client not marked revoked: {body}"
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_delete_stops_token_issuance() -> Result<()> {
    let a = actors().await?;
    let p = pid();
    let (_, rsp) = create(&a, &a.domain_id, Some(&a.admin), &p).await?;
    let client_id = rsp["oauth2_client"]["client_id"]
        .as_str()
        .ok_or_else(|| eyre!("no client_id"))?
        .to_string();
    let secret = rsp["client_secret"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    Client::new()
        .delete(url(&a.domain_id, &format!("/{p}"))?)
        .header("x-auth-token", &a.admin)
        .send()
        .await?;
    let (status, body) = post_token_form(
        &a.domain_id,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &secret),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    Ok(())
}

// ---- rotate-secret ---------------------------------------------------------

#[tokio::test]
#[traced_test]
async fn test_client_rotate_secret_invalidates_old_secret() -> Result<()> {
    let a = actors().await?;
    let p = pid();
    let (_, rsp) = create(&a, &a.domain_id, Some(&a.admin), &p).await?;
    let client_id = rsp["oauth2_client"]["client_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let old = rsp["client_secret"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let rsp = Client::new()
        .post(url(&a.domain_id, &format!("/{p}/rotate-secret"))?)
        .header("x-auth-token", &a.admin)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::OK);
    let new: Value = rsp.json().await?;
    let new = new["client_secret"]
        .as_str()
        .ok_or_else(|| eyre!("no client_secret in {new}"))?
        .to_string();
    assert_ne!(new, old);

    // Old secret no longer authenticates (introspect = Basic client auth).
    let (status, _) =
        test_api::oauth2::post_introspect_form(&a.domain_id, &client_id, &old, &[("token", "x")])
            .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) =
        test_api::oauth2::post_introspect_form(&a.domain_id, &client_id, &new, &[("token", "x")])
            .await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_rotate_secret_denied_and_unauthenticated() -> Result<()> {
    let a = actors().await?;
    let p = pid();
    create(&a, &a.domain_id, Some(&a.admin), &p).await?;
    for (token, expected) in [
        (
            Some(a.plain.as_str()),
            vec![StatusCode::FORBIDDEN, StatusCode::UNAUTHORIZED],
        ),
        (Some(a.manager.as_str()), vec![StatusCode::FORBIDDEN]),
        (None, vec![StatusCode::UNAUTHORIZED]),
    ] {
        let rsp = authed(
            Client::new().post(url(&a.domain_id, &format!("/{p}/rotate-secret"))?),
            token,
        )
        .send()
        .await?;
        assert!(expected.contains(&rsp.status()), "{}", rsp.status());
    }
    Ok(())
}
