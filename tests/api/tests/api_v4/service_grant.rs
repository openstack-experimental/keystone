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
//! Live-server service grants (ADR 0036).
//!
//! The harness serves the public interface only. A grant is redeemed with
//! an X.509-SVID on the internal interface, so these tests cover the grant
//! management API and prove that a grant can not be redeemed, nor its
//! grantee service identity assumed, through the public interface.

use eyre::{Result, eyre};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::scope::{DomainBuilder, Scope, ScopeProjectBuilder};

use test_api::common::{TestClient, get_password_auth, http_client};
use test_api::oauth2::post_token_form;
use test_api::oauth2_browser::*;
use test_api::svid_client::post_form;

const GRANT_TYPE: &str = "urn:openstack:params:oauth:grant-type:service-grant";

struct Fixture {
    domain_id: String,
    project_id: String,
    role_id: String,
    user_name: String,
    user_id: String,
    client_id: String,
}

fn bail<T>(what: &str, status: StatusCode, body: &Value) -> Result<T> {
    Err(eyre!("{what} failed with {status}: {body}"))
}

/// Send `method path` with a JSON `body` as system admin, return status and
/// parsed body.
async fn admin_call(
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<(StatusCode, Value)> {
    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;
    let mut req = admin.client.request(method, admin.base_url.join(path)?);
    if let Some(body) = body {
        req = req.json(&body);
    }
    let rsp = req.send().await?;
    let status = rsp.status();
    Ok((status, rsp.json().await.unwrap_or(Value::Null)))
}

fn id_of(body: &Value, key: &str) -> Result<String> {
    body[key]["id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| eyre!("no {key}.id in {body}"))
}

/// A domain with a user holding a role on a project, and a delegatable
/// `tls_client_auth` service whose role ceiling names that role.
async fn fixture() -> Result<Fixture> {
    fixture_with_svid(None).await
}


/// SVID of the harness SPIRE entry the redeeming test owns, and one that no
/// client is ever registered for (`tools/start-spire.sh`).
const REDEEM_SVID: &str = "spiffe://example.org/service/it-redeem/host/h1";
const FOREIGN_SVID: &str = "spiffe://example.org/service/it-foreign/host/h1";

/// Like [`fixture`], with the client's `spiffe_ids` set to the exact `svid`
/// instead of a pattern unique to the client.
async fn fixture_with_svid(svid: Option<&str>) -> Result<Fixture> {
    let domain_id = create_ready_domain("sg").await?;
    let (user_id, user_name) = create_browser_user(&domain_id).await?;

    let (status, body) = admin_call(
        reqwest::Method::POST,
        "v3/projects",
        Some(json!({"project": {
            "name": format!("sg-project-{}", Uuid::new_v4().simple()),
            "domain_id": domain_id,
        }})),
    )
    .await?;
    if !status.is_success() {
        return bail("project creation", status, &body);
    }
    let project_id = id_of(&body, "project")?;

    let (status, body) = admin_call(
        reqwest::Method::POST,
        "v3/roles",
        Some(json!({"role": {"name": format!("sg-role-{}", Uuid::new_v4().simple())}})),
    )
    .await?;
    if !status.is_success() {
        return bail("role creation", status, &body);
    }
    let role_id = id_of(&body, "role")?;

    let (status, body) = admin_call(
        reqwest::Method::PUT,
        &format!("v3/projects/{project_id}/users/{user_id}/roles/{role_id}"),
        None,
    )
    .await?;
    if !status.is_success() {
        return bail("role assignment", status, &body);
    }

    let provider_id = format!("svc-{}", Uuid::new_v4().simple());
    let client = create_browser_client(
        &domain_id,
        json!({
            "provider_id": provider_id,
            "confidential": false,
            "grant_types": [],
            "allowed_scopes": ["openstack:api"],
            "token_endpoint_auth_method": "tls_client_auth",
            "require_pkce": false,
            "redirect_uris": [],
            "post_logout_redirect_uris": [],
            "spiffe_ids": [svid.map_or_else(
                || format!("spiffe://example.org/service/{provider_id}/host/*"),
                String::from,
            )],
            "delegation": {"service_grants": true, "max_role_ids": [role_id]},
        }),
    )
    .await?;

    Ok(Fixture {
        domain_id,
        project_id,
        role_id,
        user_name,
        user_id,
        client_id: client.client_id,
    })
}

impl Fixture {
    /// The fixture user, password-authenticated and project-scoped.
    async fn user(&self) -> Result<TestClient> {
        let mut tc = TestClient::new()?;
        tc.auth_password(
            get_password_auth(&self.user_name, PASSWORD, &self.domain_id)?,
            Some(Scope::Project(
                ScopeProjectBuilder::default()
                    .id(self.project_id.clone())
                    .domain(DomainBuilder::default().id(&self.domain_id).build()?)
                    .build()?,
            )),
        )
        .await?;
        Ok(tc)
    }

    fn create_body(&self) -> Value {
        json!({"service_grant": {
            "grantee_client_id": self.client_id,
            "project_id": self.project_id,
            "role_ids": [self.role_id],
        }})
    }

    /// Create a grant as the fixture user; returns its id.
    async fn create_grant(&self, user: &TestClient) -> Result<String> {
        let rsp = user
            .client
            .post(user.base_url.join("v4/service-grants")?)
            .json(&self.create_body())
            .send()
            .await?;
        let status = rsp.status();
        let body: Value = rsp.json().await.unwrap_or(Value::Null);
        if status != StatusCode::CREATED {
            return bail("grant creation", status, &body);
        }
        id_of(&body, "service_grant")
    }
}

/// `POST /v4/oauth2/{domain}/token` with the service grant grant type and
/// whatever extra form fields, unauthenticated as the public interface sees
/// it. Returns the status and body, and asserts no token was issued.
async fn redeem_public(
    domain_id: &str,
    extra: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> Result<(StatusCode, Value)> {
    let base = base_url()?;
    let mut form = vec![("grant_type", GRANT_TYPE)];
    form.extend_from_slice(extra);
    let mut req = http_client()
        .post(base.join(&format!("v4/oauth2/{domain_id}/token"))?)
        .form(&form);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let rsp = req.send().await?;
    let status = rsp.status();
    let body: Value = rsp.json().await.unwrap_or(Value::Null);
    assert!(
        body["access_token"].is_null(),
        "public interface issued a token: {body}"
    );
    Ok((status, body))
}

#[tokio::test]
#[traced_test]
async fn test_grant_lifecycle() -> Result<()> {
    let f = fixture().await?;
    let user = f.user().await?;

    let rsp = user
        .client
        .post(user.base_url.join("v4/service-grants")?)
        .json(&f.create_body())
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::CREATED);
    let body: Value = rsp.json().await?;
    let grant = &body["service_grant"];
    let id = id_of(&body, "service_grant")?;
    assert_eq!(grant["grantor_user_id"], f.user_id.as_str());
    assert_eq!(grant["enabled"], true);
    assert_eq!(grant["domain_id"], f.domain_id.as_str());
    assert_eq!(grant["role_ids"], json!([f.role_id]));
    assert_eq!(grant["grantee"]["client_id"], f.client_id.as_str());
    assert_eq!(grant["target"]["project_id"], f.project_id.as_str());

    let rsp = user
        .client
        .get(user.base_url.join(&format!("v4/service-grants/{id}"))?)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::OK);
    let shown: Value = rsp.json().await?;
    assert_eq!(shown["service_grant"]["id"], id.as_str());

    let rsp = user
        .client
        .get(
            user.base_url
                .join(&format!("v4/service-grants?user_id={}", f.user_id))?,
        )
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::OK);
    let listed: Value = rsp.json().await?;
    assert!(
        listed["service_grants"]
            .as_array()
            .is_some_and(|g| g.iter().any(|g| g["id"] == id.as_str())),
        "{listed}"
    );

    let rsp = user
        .client
        .delete(user.base_url.join(&format!("v4/service-grants/{id}"))?)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::NO_CONTENT);
    let rsp = user
        .client
        .get(user.base_url.join(&format!("v4/service-grants/{id}"))?)
        .send()
        .await?;
    // Policy decides before a 404 can tell whether the id exists.
    assert_eq!(rsp.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_delegatable_service_hides_spiffe_ids() -> Result<()> {
    let f = fixture().await?;
    let user = f.user().await?;
    let rsp = user
        .client
        .get(user.base_url.join("v4/delegatable-services")?)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::OK);
    let raw = rsp.text().await?;
    let body: Value = serde_json::from_str(&raw)?;
    let service = body["delegatable_services"]
        .as_array()
        .and_then(|s| s.iter().find(|s| s["client_id"] == f.client_id.as_str()))
        .ok_or_else(|| eyre!("service not listed: {raw}"))?;
    assert_eq!(service["max_role_ids"], json!([f.role_id]));
    assert!(!raw.contains("spiffe"), "SPIFFE IDs leaked: {raw}");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_requires_authentication() -> Result<()> {
    let f = fixture().await?;
    let rsp = http_client()
        .post(base_url()?.join("v4/service-grants")?)
        .json(&f.create_body())
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_rejects_unusable_input() -> Result<()> {
    let f = fixture().await?;
    let user = f.user().await?;
    let post = |body: Value| {
        let url = user.base_url.join("v4/service-grants");
        let client = user.client.clone();
        async move { Ok::<_, eyre::Report>(client.post(url?).json(&body).send().await?.status()) }
    };

    // Unknown grantee.
    let status = post(json!({"service_grant": {
        "grantee_client_id": "no-such-client",
        "project_id": f.project_id,
    }}))
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A role the caller does not hold on the project.
    let status = post(json!({"service_grant": {
        "grantee_client_id": f.client_id,
        "project_id": f.project_id,
        "role_ids": [Uuid::new_v4().simple().to_string()],
    }}))
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A project the caller holds nothing on.
    let status = post(json!({"service_grant": {
        "grantee_client_id": f.client_id,
        "project_id": Uuid::new_v4().simple().to_string(),
    }}))
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_other_user_can_not_read_or_revoke_grant() -> Result<()> {
    let f = fixture().await?;
    let owner = f.user().await?;
    let id = f.create_grant(&owner).await?;

    let (_, other_name) = create_browser_user(&f.domain_id).await?;
    let mut other = TestClient::new()?;
    other
        .auth_password(
            get_password_auth(&other_name, PASSWORD, &f.domain_id)?,
            None,
        )
        .await?;

    // Another user's grant answers as an id that never existed, so the
    // response is no oracle for grant ids.
    let url = other.base_url.join(&format!("v4/service-grants/{id}"))?;
    let missing = other
        .base_url
        .join(&format!("v4/service-grants/{}", Uuid::new_v4().simple()))?;
    for url in [url.clone(), missing.clone()] {
        assert_eq!(
            other.client.get(url).send().await?.status(),
            StatusCode::FORBIDDEN
        );
    }
    for url in [url, missing] {
        assert_eq!(
            other.client.delete(url).send().await?.status(),
            StatusCode::FORBIDDEN
        );
    }

    // Still there for the owner.
    let rsp = owner
        .client
        .get(owner.base_url.join(&format!("v4/service-grants/{id}"))?)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_unauthenticated_caller_can_not_read_or_revoke_grant() -> Result<()> {
    let f = fixture().await?;
    let owner = f.user().await?;
    let id = f.create_grant(&owner).await?;

    // The grantee service reads and revokes its grants on the internal
    // interface with its SVID only. On the public one no identity claim is
    // accepted: not a missing token, not a forged client certificate header.
    let url = base_url()?.join(&format!("v4/service-grants/{id}"))?;
    for headers in [
        vec![],
        vec![(
            "x-forwarded-client-cert",
            "URI=spiffe://example.org/service/x",
        )],
        vec![("x-ssl-client-s-dn", "spiffe://example.org/service/x")],
    ] {
        let mut get = http_client().get(url.clone());
        let mut delete = http_client().delete(url.clone());
        for (name, value) in &headers {
            get = get.header(*name, *value);
            delete = delete.header(*name, *value);
        }
        assert_eq!(get.send().await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(delete.send().await?.status(), StatusCode::UNAUTHORIZED);
    }

    let rsp = owner.client.get(url).send().await?;
    assert_eq!(rsp.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_grant_can_not_be_redeemed_on_public_interface() -> Result<()> {
    let f = fixture().await?;
    let owner = f.user().await?;
    let id = f.create_grant(&owner).await?;

    // The grant is live and the client is its grantee, yet the public
    // interface refuses to redeem it.
    let (status, body) = redeem_public(
        &f.domain_id,
        &[("grant_id", &id), ("client_id", &f.client_id)],
        &[],
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");

    // Without the client id, or without the grant id.
    let (status, body) = redeem_public(&f.domain_id, &[("grant_id", &id)], &[]).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    let (status, body) = redeem_public(&f.domain_id, &[("client_id", &f.client_id)], &[]).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");

    // The grant is untouched: still enabled and never redeemed.
    let rsp = owner
        .client
        .get(owner.base_url.join(&format!("v4/service-grants/{id}"))?)
        .send()
        .await?;
    let shown: Value = rsp.json().await?;
    assert_eq!(shown["service_grant"]["enabled"], true);
    assert!(shown["service_grant"]["last_redeemed_at"].is_null());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_public_interface_ignores_forged_identity() -> Result<()> {
    let f = fixture().await?;
    let owner = f.user().await?;
    let id = f.create_grant(&owner).await?;

    // The server reads no identity from request headers: the SVID comes
    // only from the mTLS handshake of the internal listener. Claim the
    // grantee's SPIFFE ID through the channels a proxy would use anyway.
    let spiffe = format!("spiffe://example.org/service/{}/host/h1", f.client_id);
    let (status, body) = redeem_public(
        &f.domain_id,
        &[
            ("grant_id", &id),
            ("client_id", &f.client_id),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", "eyJhbGciOiJub25lIn0.e30."),
        ],
        &[
            ("x-forwarded-client-cert", &format!("URI={spiffe}")),
            ("x-ssl-client-s-dn", &spiffe),
            ("x-spiffe-id", &spiffe),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_user_token_can_not_redeem_grant() -> Result<()> {
    let f = fixture().await?;
    let owner = f.user().await?;
    let id = f.create_grant(&owner).await?;
    let token = owner
        .token
        .as_ref()
        .map(secrecy::ExposeSecret::expose_secret)
        .ok_or_else(|| eyre!("user is not authenticated"))?;

    // Even the grantor, with a valid Keystone token, can not consume their
    // own grant: redemption is the service's alone.
    let (status, body) = redeem_public(
        &f.domain_id,
        &[("grant_id", &id), ("client_id", &f.client_id)],
        &[
            ("x-auth-token", token),
            ("authorization", &format!("Bearer {token}")),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_unknown_grant_not_distinguishable_on_public_interface() -> Result<()> {
    let f = fixture().await?;
    let owner = f.user().await?;
    let id = f.create_grant(&owner).await?;

    // A live and a nonexistent grant answer alike, so the public token
    // endpoint is no oracle for grant ids.
    let live = redeem_public(&f.domain_id, &[("grant_id", &id)], &[]).await?;
    let unknown = redeem_public(
        &f.domain_id,
        &[("grant_id", &Uuid::new_v4().simple().to_string())],
        &[],
    )
    .await?;
    assert_eq!(live, unknown);

    // The ordinary token form helper agrees.
    let (status, body) = post_token_form(
        &f.domain_id,
        &[("grant_type", GRANT_TYPE), ("grant_id", &id)],
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_internal_interface_refuses_clients_without_svid() -> Result<()> {
    // The only place a grant is redeemed. Without an SVID the mTLS handshake
    // fails, so no request reaches the token endpoint, whatever the client
    // presents in it.
    // The listener is up: a refusal below is the handshake, not a closed port.
    std::net::TcpStream::connect("127.0.0.1:8215")?;
    for scheme in ["https", "http"] {
        let rsp = http_client()
            .post(format!("{scheme}://127.0.0.1:8215/v4/oauth2/default/token"))
            .form(&[("grant_type", GRANT_TYPE), ("grant_id", "x")])
            .send()
            .await;
        assert!(rsp.is_err(), "{scheme} request reached the internal port");
    }
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_grant_can_be_redeemed_with_svid_on_internal_interface() -> Result<()> {
    let f = fixture_with_svid(Some(REDEEM_SVID)).await?;
    let owner = f.user().await?;
    let id = f.create_grant(&owner).await?;
    let path = format!("/v4/oauth2/{}/token", f.domain_id);
    let form = [
        ("grant_type", GRANT_TYPE),
        ("grant_id", id.as_str()),
        ("client_id", f.client_id.as_str()),
    ];

    // The grantee's real X.509-SVID, from the SPIRE agent, over mTLS.
    let (status, body) = post_form(REDEEM_SVID, &path, &form).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"]
        .as_str()
        .ok_or_else(|| eyre!("no access_token in {body}"))?;

    // The token is issued to the grantor, acted for by the SVID.
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| eyre!("access token is not a JWT"))?;
    let claims: Value =
        serde_json::from_slice(&data_encoding::BASE64URL_NOPAD.decode(payload.as_bytes())?)?;
    assert_eq!(claims["sub"], f.user_id.as_str(), "{claims}");
    assert_eq!(claims["act"]["sub"], REDEEM_SVID, "{claims}");
    assert_eq!(claims["act"]["sub_type"], "spiffe", "{claims}");

    // A grant is a standing delegation: it redeems again, and records it.
    let (status, body) = post_form(REDEEM_SVID, &path, &form).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rsp = owner
        .client
        .get(owner.base_url.join(&format!("v4/service-grants/{id}"))?)
        .send()
        .await?;
    let shown: Value = rsp.json().await?;
    assert!(
        !shown["service_grant"]["last_redeemed_at"].is_null(),
        "{shown}"
    );

    // Revoking it ends redemption.
    let rsp = owner
        .client
        .delete(owner.base_url.join(&format!("v4/service-grants/{id}"))?)
        .send()
        .await?;
    assert!(rsp.status().is_success(), "{}", rsp.status());
    let (status, body) = post_form(REDEEM_SVID, &path, &form).await?;
    assert!(!status.is_success(), "revoked grant redeemed: {body}");
    assert!(body["access_token"].is_null(), "{body}");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_other_svid_can_not_redeem_grant() -> Result<()> {
    // The client is bound to a pattern of its own; the SVID presented is
    // valid for the trust domain but not one of the client's `spiffe_ids`.
    let f = fixture().await?;
    let owner = f.user().await?;
    let id = f.create_grant(&owner).await?;
    let path = format!("/v4/oauth2/{}/token", f.domain_id);

    let (status, body) = post_form(
        FOREIGN_SVID,
        &path,
        &[
            ("grant_type", GRANT_TYPE),
            ("grant_id", &id),
            ("client_id", &f.client_id),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    assert!(body["access_token"].is_null(), "{body}");

    // The grant is untouched.
    let rsp = owner
        .client
        .get(owner.base_url.join(&format!("v4/service-grants/{id}"))?)
        .send()
        .await?;
    let shown: Value = rsp.json().await?;
    assert_eq!(shown["service_grant"]["enabled"], true, "{shown}");
    Ok(())
}
