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
//! Ending the upstream IdP session on logout (opt-in via
//! `[oauth2] upstream_logout`).
//!
//! After the local logout the browser is sent to the IdP's
//! `end_session_endpoint`. The IdP can only return it to a URI registered
//! with it, so that is always `GET /v4/oauth2/{domain_id}/logout/complete`;
//! the relying party's own `post_logout_redirect_uri` waits in a short-lived
//! cookie. The cookie is not trusted: the endpoint checks the URI against the
//! client's registered `post_logout_redirect_uris` again.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::federation::IdentityProvider;
use openstack_keystone_core_types::oauth2_session::SsoSession;

use super::authorize::{cookie_secure, redirect_with_params};
use super::html::{logout_page, too_many_requests};
use super::renderer::LogoutCtx;
use crate::api::common::PeerAddr;
use crate::api::v4::oauth2::well_known::base_url;
use crate::federation::api::auth::upstream_end_session_url;
use crate::keystone::ServiceState;

const RETURN_COOKIE_NAME: &str = "keystone_oauth2_logout_return";

/// Lifetime of the return cookie: the round trip through the IdP.
const RETURN_COOKIE_MINUTES: i64 = 10;

/// Where the browser goes once the upstream IdP is done.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct ReturnTo {
    pub client_id: String,
    pub post_logout_redirect_uri: String,
    #[serde(default)]
    pub state: String,
}

fn return_cookie(
    value: String,
    domain_id: &str,
    secure: bool,
    max_age_minutes: i64,
) -> Cookie<'static> {
    // `Lax` so the cookie comes along with the IdP's top-level redirect.
    Cookie::build((RETURN_COOKIE_NAME, value))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .path(format!("/v4/oauth2/{domain_id}/logout/complete"))
        .max_age(time::Duration::minutes(max_age_minutes))
        .build()
}

/// What to do after a local logout of a session that came from an upstream
/// IdP.
pub(super) struct UpstreamLogout {
    /// The IdP's `end_session_endpoint` with the parameters set.
    pub url: String,
    /// Remembers the relying party's redirect; absent when there is none.
    pub cookie: Option<Cookie<'static>>,
}

/// The upstream logout for `sso`, when enabled and possible. `None` (logged)
/// leaves the logout local-only.
pub(super) async fn begin(
    state: &ServiceState,
    headers: &HeaderMap,
    domain_id: &str,
    sso: &SsoSession,
    return_to: Option<ReturnTo>,
) -> Option<UpstreamLogout> {
    let upstream = sso.upstream.as_ref()?;
    if !state
        .config_manager
        .config
        .read()
        .await
        .oauth2
        .upstream_logout
    {
        return None;
    }
    let idp = load_idp(state, domain_id, &upstream.idp_id).await?;
    let complete = format!(
        "{}/v4/oauth2/{domain_id}/logout/complete",
        base_url(state, headers).await
    );
    let url = upstream_end_session_url(&idp, &complete).await?;
    let secure = cookie_secure(state, headers).await;
    let cookie = return_to
        .and_then(|r| serde_urlencoded::to_string(&r).ok())
        .map(|value| return_cookie(value, domain_id, secure, RETURN_COOKIE_MINUTES));
    Some(UpstreamLogout { url, cookie })
}

async fn load_idp(state: &ServiceState, domain_id: &str, idp_id: &str) -> Option<IdentityProvider> {
    match state
        .provider
        .get_federation_provider()
        .get_identity_provider(&ExecutionContext::internal(state), idp_id)
        .await
    {
        Ok(Some(idp)) if idp.domain_id.as_deref() == Some(domain_id) => Some(idp),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(error = %e, idp_id, "upstream logout: identity provider lookup failed");
            None
        }
    }
}

/// `GET /v4/oauth2/{domain_id}/logout/complete`.
#[utoipa::path(
    get,
    path = "/{domain_id}/logout/complete",
    operation_id = "/oauth2:logout_complete",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "Signed-out page", content_type = "text/html"),
        (status = SEE_OTHER, description = "Redirect to the registered post_logout_redirect_uri"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::logout_complete",
    level = "debug",
    skip(state),
    err(Debug)
)]
pub(super) async fn logout_complete(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    jar: CookieJar,
) -> Result<Response, std::convert::Infallible> {
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|a| a.ip()))
    {
        return Ok(too_many_requests(retry_after.as_secs()));
    }
    let secure = cookie_secure(&state, &headers).await;
    let clear = return_cookie(String::new(), &domain_id, secure, 0);
    let response = match jar
        .get(RETURN_COOKIE_NAME)
        .and_then(|c| serde_urlencoded::from_str::<ReturnTo>(c.value()).ok())
    {
        Some(r) => registered_redirect(&state, &domain_id, &r)
            .await
            .map_or_else(signed_out, |uri| {
                redirect_with_params(&uri, &[("state", &r.state)])
            }),
        None => signed_out(),
    };
    Ok((CookieJar::new().add(clear), response).into_response())
}

fn signed_out() -> Response {
    logout_page(&LogoutCtx {
        confirm: false,
        action: String::new(),
        fields: Vec::new(),
        frames: Vec::new(),
        refresh: None,
        refresh_seconds: 0,
    })
}

/// The redirect URI of `r`, if the client still has it registered.
async fn registered_redirect(
    state: &ServiceState,
    domain_id: &str,
    r: &ReturnTo,
) -> Option<String> {
    let client = state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&ExecutionContext::internal(state), &r.client_id)
        .await
        .ok()
        .flatten()?;
    (client.enabled
        && client.deleted_at.is_none()
        && client.domain_id == domain_id
        && client
            .post_logout_redirect_uris
            .iter()
            .any(|u| u == &r.post_logout_redirect_uri))
    .then(|| r.post_logout_redirect_uri.clone())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;

    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::oauth2_client::{GrantType, OAuth2ClientResource};

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state_with_config;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::Provider;

    fn client(enabled: bool) -> OAuth2ClientResource {
        OAuth2ClientResource {
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: "domain-1".into(),
            client_secret_hash: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec![GrantType::AuthorizationCode],
            require_pkce: true,
            allowed_scopes: vec!["openid".into()],
            pre_authorized: false,
            enabled,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
            name: "Example App".into(),
            description: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
            post_logout_redirect_uris: vec!["https://rp.example.com/bye".into()],
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            spiffe_ids: vec![],
            delegation: None,
            dpop_bound_access_tokens: false,
        }
    }

    async fn complete(cookie: Option<&str>, enabled: bool) -> axum::response::Response {
        let mut clients = MockOauth2ClientProvider::default();
        clients
            .expect_get_by_client_id()
            .returning(move |_, id| Ok((id == "client-1").then(|| client(enabled))));
        let mut config = Config::default();
        config.oauth2.allow_host_header_issuer = true;
        let state = get_mocked_state_with_config(
            Provider::mocked_builder().mock_oauth2_client(clients),
            true,
            None,
            config,
        )
        .await;
        let (router, _) = openapi_router().split_for_parts();
        let mut request = Request::builder().uri("/domain-1/logout/complete");
        if let Some(cookie) = cookie {
            request = request.header(
                header::COOKIE,
                format!("keystone_oauth2_logout_return={cookie}"),
            );
        }
        router
            .with_state(state)
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    fn return_to(uri: &str) -> String {
        serde_urlencoded::to_string(super::ReturnTo {
            client_id: "client-1".into(),
            post_logout_redirect_uri: uri.into(),
            state: "xyz".into(),
        })
        .unwrap()
        .replace('%', "%25")
    }

    #[tokio::test]
    async fn test_complete_redirects_to_the_remembered_uri() {
        let response = complete(Some(&return_to("https://rp.example.com/bye")), true).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        assert!(
            location.starts_with("https://rp.example.com/bye"),
            "{location}"
        );
        assert!(location.contains("state=xyz"), "{location}");
        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(cookie.contains("Max-Age=0"), "{cookie}");
    }

    #[tokio::test]
    async fn test_complete_ignores_a_tampered_uri() {
        let response = complete(Some(&return_to("https://evil.example.com/")), true).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_complete_ignores_the_uri_of_a_disabled_client() {
        let response = complete(Some(&return_to("https://rp.example.com/bye")), false).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_complete_without_a_cookie_shows_the_signed_out_page() {
        let response = complete(None, true).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
