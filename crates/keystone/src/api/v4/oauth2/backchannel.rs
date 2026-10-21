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
//! OIDC Back-Channel Logout 1.0.
//!
//! When a user's sign-in session ends, every client that was issued an
//! authorization code for the user and registered a `backchannel_logout_uri`
//! receives a signed `logout_token` by `POST`. The token carries the user as
//! `sub` and no `sid`: id tokens do not carry a session id, so the logout
//! applies to all the user's sessions at the relying party and discovery
//! reports `backchannel_logout_session_supported: false`.
//!
//! Delivery is best effort and never blocks the operation that ended the
//! session. Each target is tried a few times with a growing delay in a
//! detached task. The endpoint is untrusted input: the host is resolved
//! here, refused when it is a private, loopback, link-local or otherwise
//! internal address, and the connection is pinned to the validated address.
//! Redirects are never followed.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use tokio::task::JoinHandle;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::auth_plugin::resolve_public_addr;
use openstack_keystone_core::oauth2_session::{Oauth2SessionProviderError, derive_sid};
use openstack_keystone_core_types::oauth2_client::OAuth2ClientResource;

use openstack_keystone_core::events::ProviderHooks;
use openstack_keystone_core_types::events::{
    Event, EventPayload, Operation, PASSWORD_CHANGE_OPERATION,
};

use super::token::sign_jwt_typed;
use crate::keystone::ServiceState;

/// `events` member identifying a back-channel logout token.
const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// Lifetime of a logout token; the RP rejects it afterwards.
const LOGOUT_TOKEN_LIFETIME_SECS: i64 = 120;

/// Per-attempt timeout of the request to the relying party.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Claims of a logout token (OIDC Back-Channel Logout 1.0 §2.4).
#[derive(Debug, Serialize)]
struct LogoutTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    exp: i64,
    jti: String,
    events: serde_json::Value,
    /// Session identifier; equals the `sid` of the RP's id_token.
    #[serde(skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
}

/// How a logout token reaches a relying party.
#[async_trait]
pub trait LogoutTransport: Send + Sync {
    /// `POST logout_token=<token>` to `url`; returns the HTTP status.
    async fn post(&self, url: &str, logout_token: &str) -> Result<u16, String>;
}

/// Production transport: SSRF-validated, address-pinned `reqwest`.
#[derive(Debug, Default)]
pub struct ReqwestLogoutTransport;

#[async_trait]
impl LogoutTransport for ReqwestLogoutTransport {
    async fn post(&self, url: &str, logout_token: &str) -> Result<u16, String> {
        let parsed = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
        if parsed.scheme() != "https" {
            return Err("backchannel_logout_uri must be https".to_string());
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| "url has no host".to_string())?
            .to_string();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| "url has no port".to_string())?;
        // Re-resolved on every attempt, then pinned: a name that later points
        // at an internal address (DNS rebinding) is refused.
        let addr = resolve_public_addr(&host, port).await?;
        openstack_keystone_tls_provider::install_default();
        let client = reqwest::Client::builder()
            .resolve(&host, addr)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| e.to_string())?;
        let response = client
            .post(parsed)
            .header(reqwest::header::CACHE_CONTROL, "no-store")
            .form(&[("logout_token", logout_token)])
            .send()
            .await
            .map_err(|e| e.to_string())?;
        Ok(response.status().as_u16())
    }
}

/// Delays between the attempts to reach one relying party; the first
/// attempt is immediate.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub delays: Vec<Duration>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            delays: vec![Duration::from_secs(2), Duration::from_secs(10)],
        }
    }
}

/// Build and sign the logout token of `user_id` for `client`.
async fn logout_token(
    state: &ServiceState,
    base_url: &str,
    client: &OAuth2ClientResource,
    user_id: &str,
    sid: Option<String>,
) -> Result<String, String> {
    let now = chrono::Utc::now().timestamp();
    let claims = LogoutTokenClaims {
        iss: format!("{base_url}/v4/oauth2/{}", client.domain_id),
        sub: user_id.to_string(),
        aud: client.client_id.clone(),
        iat: now,
        exp: now + LOGOUT_TOKEN_LIFETIME_SECS,
        jti: uuid::Uuid::new_v4().to_string(),
        events: serde_json::json!({ LOGOUT_EVENT: {} }),
        sid,
    };
    sign_jwt_typed(state, &client.domain_id, &claims, Some("logout+jwt"))
        .await
        .map_err(|_| "logout token signing failed".to_string())
}

/// Deliver one logout token, retrying per `policy`. `true` when the relying
/// party acknowledged with `200` or `204`.
async fn deliver(
    transport: &dyn LogoutTransport,
    policy: &RetryPolicy,
    client_id: &str,
    url: &str,
    token: &str,
) -> bool {
    let attempts = policy.delays.len() + 1;
    for attempt in 0..attempts {
        if attempt > 0 {
            tokio::time::sleep(policy.delays[attempt - 1]).await;
        }
        match transport.post(url, token).await {
            Ok(200 | 204) => return true,
            Ok(status) => {
                tracing::warn!(client_id, status, attempt, "back-channel logout refused");
            }
            Err(e) => {
                tracing::warn!(client_id, error = %e, attempt, "back-channel logout failed");
            }
        }
    }
    tracing::warn!(client_id, attempts, "back-channel logout gave up");
    false
}

/// What ended: every session of the user, or one SSO session.
#[derive(Clone, Copy, Debug)]
pub enum EndedSessions<'a> {
    /// All sessions of the user (disabled, deleted, password changed).
    AllOfUser,
    /// The SSO session with this reference (`sso_ref`): logout, expiry,
    /// eviction, domain disable or delete.
    Sso(&'a str),
}

/// Tell every relying party of `user_id` that registered a
/// `backchannel_logout_uri` that the session ended, forgetting the relying
/// parties as it takes them. `base_url` is the public endpoint (no trailing
/// slash).
///
/// Returns the delivery tasks: production callers drop them (fire and
/// forget); tests await them.
pub async fn notify_logout(
    state: &ServiceState,
    transport: Arc<dyn LogoutTransport>,
    policy: RetryPolicy,
    base_url: &str,
    user_id: &str,
    ended: EndedSessions<'_>,
) -> Vec<JoinHandle<bool>> {
    notify_logout_with_frontchannel(state, transport, policy, base_url, user_id, ended)
        .await
        .tasks
}

/// A relying party to notify through the user's browser (OIDC Front-Channel
/// Logout 1.0 §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontchannelTarget {
    /// `frontchannel_logout_uri` with `iss` and `sid` appended when the RP
    /// requires them.
    pub url: String,
    /// Origin of the URI, for the page's `frame-src`.
    pub origin: String,
}

/// Outcome of [`notify_logout_with_frontchannel`].
pub struct LogoutNotice {
    /// Back-channel delivery tasks.
    pub tasks: Vec<JoinHandle<bool>>,
    /// Relying parties to be notified by the browser.
    pub frontchannel: Vec<FrontchannelTarget>,
}

fn frontchannel_target(
    client: &OAuth2ClientResource,
    base_url: &str,
    domain_id: &str,
    sid: Option<&str>,
) -> Option<FrontchannelTarget> {
    let uri = client
        .frontchannel_logout_uri
        .as_deref()
        .filter(|u| !u.is_empty())?;
    let mut url = url::Url::parse(uri).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    if client.frontchannel_logout_session_required {
        // The RP asked for `iss` and `sid`; without a session id it cannot
        // tell which session to end.
        let sid = sid?;
        url.query_pairs_mut()
            .append_pair("iss", &format!("{base_url}/v4/oauth2/{domain_id}"))
            .append_pair("sid", sid);
    }
    let origin = url.origin().ascii_serialization();
    Some(FrontchannelTarget {
        url: url.to_string(),
        origin,
    })
}

/// [`notify_logout`] that also reports the relying parties with a
/// front-channel logout URI.
pub async fn notify_logout_with_frontchannel(
    state: &ServiceState,
    transport: Arc<dyn LogoutTransport>,
    policy: RetryPolicy,
    base_url: &str,
    user_id: &str,
    ended: EndedSessions<'_>,
) -> LogoutNotice {
    let mut frontchannel = Vec::new();
    let sessions = state.provider.get_oauth2_session_provider();
    // List and clear in one step: the relying parties removed are exactly
    // the ones notified, so one recorded in between is kept for the next
    // logout instead of being dropped unnotified.
    let removed = match ended {
        EndedSessions::AllOfUser => sessions.delete_rp_sessions_by_user(state, user_id).await,
        EndedSessions::Sso(sso_ref) => {
            sessions
                .delete_rp_sessions_by_sso(state, user_id, sso_ref)
                .await
        }
    };
    let rps = match removed {
        Ok(rps) => rps,
        // No raft storage, no OP sessions, nothing to notify.
        Err(Oauth2SessionProviderError::RaftNotAvailable) => {
            return LogoutNotice {
                tasks: Vec::new(),
                frontchannel,
            };
        }
        Err(e) => {
            tracing::warn!(error = %e, "back-channel logout: relying parties not cleared");
            return LogoutNotice {
                tasks: Vec::new(),
                frontchannel,
            };
        }
    };

    let exec = ExecutionContext::internal(state);
    let mut tasks = Vec::new();
    // Whether the user still has another browser session, looked up once and
    // only if a relying party needs it.
    let mut other_sessions: Option<bool> = None;
    for rp in rps {
        let client_id = rp.client_id;
        let client = match state
            .provider
            .get_oauth2_client_provider()
            .get_by_client_id(&exec, &client_id)
            .await
        {
            Ok(Some(c)) if c.enabled && c.deleted_at.is_none() => c,
            Ok(_) => continue,
            Err(e) => {
                tracing::warn!(client_id, error = %e, "back-channel logout: client lookup failed");
                continue;
            }
        };
        let sid = rp
            .sso_ref
            .as_deref()
            .map(|sso_ref| derive_sid(sso_ref, &client_id));
        frontchannel.extend(frontchannel_target(
            &client,
            base_url,
            &client.domain_id,
            sid.as_deref(),
        ));
        let Some(url) = client
            .backchannel_logout_uri
            .clone()
            .filter(|u| !u.is_empty())
        else {
            continue;
        };
        if client.backchannel_logout_session_required && sid.is_none() {
            // The RP never received a `sid` (grant without an SSO
            // session), so it cannot match a token that must carry one.
            tracing::debug!(
                client_id,
                "back-channel logout: no session id for an RP that requires it"
            );
            continue;
        }
        if matches!(ended, EndedSessions::Sso(_)) && !client.backchannel_logout_session_required {
            // Without `sid` support the RP may take the token as "log the
            // user out everywhere", which would end the sessions the user
            // still has in other browsers.
            let remain = match other_sessions {
                Some(remain) => remain,
                None => {
                    let remain = match sessions
                        .list_sso_sessions_by_user(state, &client.domain_id, user_id)
                        .await
                    {
                        Ok(s) => !s.is_empty(),
                        // Unknown: do not log the user out of other sessions.
                        Err(_) => true,
                    };
                    other_sessions = Some(remain);
                    remain
                }
            };
            if remain {
                tracing::debug!(
                    client_id,
                    "back-channel logout: user has other sessions and the RP does not require a sid"
                );
                continue;
            }
        }
        let token = match logout_token(state, base_url, &client, user_id, sid).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(client_id, error = %e, "back-channel logout: no token");
                continue;
            }
        };
        let transport = Arc::clone(&transport);
        let policy = policy.clone();
        tasks.push(tokio::spawn(async move {
            deliver(transport.as_ref(), &policy, &client_id, &url, &token).await
        }));
    }
    LogoutNotice {
        tasks,
        frontchannel,
    }
}

/// [`notify_logout`] for every session of the user.
pub async fn notify_user_logout(
    state: &ServiceState,
    transport: Arc<dyn LogoutTransport>,
    policy: RetryPolicy,
    base_url: &str,
    user_id: &str,
) -> Vec<JoinHandle<bool>> {
    notify_logout(
        state,
        transport,
        policy,
        base_url,
        user_id,
        EndedSessions::AllOfUser,
    )
    .await
}

/// Hook that sends back-channel logout when a user is deleted, disabled or
/// changes their password: the OP then ends their sessions without a browser
/// ever reaching the logout endpoint. Needs a configured `public_endpoint`
/// (there is no request to take the issuer from).
pub struct BackchannelLogoutHook {
    state: ServiceState,
    transport: Arc<dyn LogoutTransport>,
    policy: RetryPolicy,
    /// Whether the missing `public_endpoint` was reported already.
    warned_no_endpoint: std::sync::atomic::AtomicBool,
}

impl BackchannelLogoutHook {
    /// Create the hook with the production transport.
    pub fn new(state: ServiceState) -> Self {
        Self {
            state,
            transport: Arc::new(ReqwestLogoutTransport),
            policy: RetryPolicy::default(),
            warned_no_endpoint: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl ProviderHooks for BackchannelLogoutHook {
    async fn on_event(&self, event: &Event) {
        let (user_id, ended) = match (&event.operation, &event.payload) {
            (Operation::Delete | Operation::Disable, EventPayload::User { id }) => {
                (id, EndedSessions::AllOfUser)
            }
            (Operation::Other(op), EventPayload::User { id })
                if op == PASSWORD_CHANGE_OPERATION =>
            {
                (id, EndedSessions::AllOfUser)
            }
            // One session ended: logout, expiry, eviction, domain
            // disable or delete.
            (
                Operation::Delete,
                EventPayload::Oauth2SsoSession {
                    user_id, sso_ref, ..
                },
            ) => (user_id, EndedSessions::Sso(sso_ref)),
            _ => return,
        };
        let Some(base_url) = self
            .state
            .config_manager
            .config
            .read()
            .await
            .default
            .public_endpoint
            .as_ref()
            .map(|u| u.to_string().trim_end_matches('/').to_string())
        else {
            // Say it once: otherwise no notice is ever sent and nothing
            // tells the operator why.
            if !self
                .warned_no_endpoint
                .swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                tracing::warn!(
                    "back-channel logout on user disable, delete or password change is off: \
                     `[DEFAULT] public_endpoint` is not configured"
                );
            }
            return;
        };
        drop(
            notify_logout(
                &self.state,
                Arc::clone(&self.transport),
                self.policy.clone(),
                &base_url,
                user_id,
                ended,
            )
            .await,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use jsonwebtoken::{Algorithm, Validation, decode};

    use super::*;
    use crate::api::tests::get_mocked_state;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;
    use openstack_keystone_core_types::oauth2_client::GrantType;
    use openstack_keystone_core_types::oauth2_session::{RpSession, SsoSession};
    use openstack_keystone_key_repository::asymmetric::{
        KeyMaterial, SigningAlgorithm, generate_keypair, to_decoding_key,
    };

    /// Records every request and answers with the scripted statuses.
    struct Recorder {
        calls: Mutex<Vec<(String, String)>>,
        statuses: Mutex<Vec<Result<u16, String>>>,
    }

    impl Recorder {
        fn new(statuses: Vec<Result<u16, String>>) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                statuses: Mutex::new(statuses),
            })
        }
    }

    #[async_trait]
    impl LogoutTransport for Recorder {
        async fn post(&self, url: &str, logout_token: &str) -> Result<u16, String> {
            self.calls
                .lock()
                .unwrap()
                .push((url.to_string(), logout_token.to_string()));
            let mut statuses = self.statuses.lock().unwrap();
            if statuses.is_empty() {
                Ok(200)
            } else {
                statuses.remove(0)
            }
        }
    }

    #[test]
    fn test_frontchannel_target_adds_iss_and_sid_only_when_required() {
        let mut c = client("c", None);
        c.frontchannel_logout_uri = Some("https://rp.example.com/fc?x=1".into());
        let plain = frontchannel_target(&c, "https://op", "d1", Some("sid-1")).unwrap();
        assert_eq!(plain.url, "https://rp.example.com/fc?x=1");
        assert_eq!(plain.origin, "https://rp.example.com");

        c.frontchannel_logout_session_required = true;
        let with_sid = frontchannel_target(&c, "https://op", "d1", Some("sid-1")).unwrap();
        assert_eq!(
            with_sid.url,
            "https://rp.example.com/fc?x=1&iss=https%3A%2F%2Fop%2Fv4%2Foauth2%2Fd1&sid=sid-1"
        );
        assert!(frontchannel_target(&c, "https://op", "d1", None).is_none());
    }

    #[test]
    fn test_frontchannel_target_requires_https() {
        let mut c = client("c", None);
        c.frontchannel_logout_uri = Some("http://rp.example.com/fc".into());
        assert!(frontchannel_target(&c, "https://op", "d1", None).is_none());
        c.frontchannel_logout_uri = None;
        assert!(frontchannel_target(&c, "https://op", "d1", None).is_none());
    }

    fn client(id: &str, uri: Option<&str>) -> OAuth2ClientResource {
        OAuth2ClientResource {
            client_id: id.into(),
            provider_id: "p".into(),
            domain_id: "domain-1".into(),
            client_secret_hash: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec![GrantType::AuthorizationCode],
            require_pkce: true,
            allowed_scopes: vec!["openid".into()],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
            name: id.into(),
            description: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: uri.map(str::to_string),
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            spiffe_ids: vec![],
            delegation: None,
            dpop_bound_access_tokens: false,
        }
    }

    fn fast() -> RetryPolicy {
        RetryPolicy {
            delays: vec![Duration::ZERO, Duration::ZERO],
        }
    }

    async fn state_with(
        rp_clients: Vec<&'static str>,
        clients: Vec<OAuth2ClientResource>,
        public_key: Arc<Mutex<Option<KeyMaterial>>>,
    ) -> ServiceState {
        state_with_other_sessions(rp_clients, clients, public_key, Vec::new()).await
    }

    async fn state_with_other_sessions(
        rp_clients: Vec<&'static str>,
        clients: Vec<OAuth2ClientResource>,
        public_key: Arc<Mutex<Option<KeyMaterial>>>,
        other: Vec<SsoSession>,
    ) -> ServiceState {
        // A relying party called `device` was issued without an SSO session.
        let rps: Vec<RpSession> = rp_clients
            .iter()
            .map(|c| RpSession {
                client_id: c.to_string(),
                sso_ref: (*c != "device").then(|| "ref-1".to_string()),
            })
            .collect();
        let by_sso = rps.clone();
        let mut sessions = MockOauth2SessionProvider::default();
        sessions
            .expect_delete_rp_sessions_by_user()
            .returning(move |_, _| Ok(rps.clone()));
        sessions
            .expect_delete_rp_sessions_by_sso()
            .returning(move |_, _, _| Ok(by_sso.clone()));
        sessions
            .expect_list_sso_sessions_by_user()
            .returning(move |_, _, _| Ok(other.clone()));
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, id| Ok(clients.iter().find(|c| c.client_id == id).cloned()));
        let mut keys = crate::oauth2_key::MockOauth2KeyProvider::default();
        keys.expect_active_signing_key().returning(move |_, _| {
            let key = generate_keypair(SigningAlgorithm::Es256).unwrap();
            *public_key.lock().unwrap() = Some(key.clone());
            Ok(key)
        });
        get_mocked_state(
            Provider::mocked_builder()
                .mock_oauth2_session(sessions)
                .mock_oauth2_client(client_mock)
                .mock_oauth2_key(keys),
            true,
            None,
        )
        .await
    }

    #[tokio::test]
    async fn test_sends_a_signed_logout_token_to_registered_clients_only() {
        let public_key = Arc::new(Mutex::new(None));
        let state = state_with(
            vec!["with-uri", "without-uri", "unknown"],
            vec![
                client("with-uri", Some("https://rp.example.com/bc")),
                client("without-uri", None),
            ],
            public_key.clone(),
        )
        .await;
        let transport = Recorder::new(vec![]);
        let tasks = notify_user_logout(
            &state,
            transport.clone(),
            fast(),
            "https://keystone.example.com",
            "user-1",
        )
        .await;
        assert_eq!(tasks.len(), 1);
        for task in tasks {
            assert!(task.await.unwrap());
        }

        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "https://rp.example.com/bc");

        let header = jsonwebtoken::decode_header(&calls[0].1).unwrap();
        assert_eq!(header.typ.as_deref(), Some("logout+jwt"));
        let key = public_key.lock().unwrap().clone().unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&["with-uri"]);
        validation.set_issuer(&["https://keystone.example.com/v4/oauth2/domain-1"]);
        let data =
            decode::<serde_json::Value>(&calls[0].1, &to_decoding_key(&key).unwrap(), &validation)
                .unwrap();
        assert_eq!(data.claims["sub"], "user-1");
        assert!(data.claims["events"][LOGOUT_EVENT].is_object());
        assert!(data.claims.get("nonce").is_none());
        assert!(data.claims["jti"].as_str().is_some_and(|j| !j.is_empty()));
    }

    async fn token_claims(
        public_key: &Arc<Mutex<Option<KeyMaterial>>>,
        token: &str,
        aud: &str,
    ) -> serde_json::Value {
        let key = public_key.lock().unwrap().clone().unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&[aud]);
        decode::<serde_json::Value>(token, &to_decoding_key(&key).unwrap(), &validation)
            .unwrap()
            .claims
    }

    #[tokio::test]
    async fn test_session_logout_token_carries_the_sid_of_the_id_token() {
        let public_key = Arc::new(Mutex::new(None));
        let state = state_with(
            vec!["c"],
            vec![client("c", Some("https://rp.example.com/bc"))],
            public_key.clone(),
        )
        .await;
        let transport = Recorder::new(vec![]);
        let tasks = notify_logout(
            &state,
            transport.clone(),
            fast(),
            "https://k",
            "user-1",
            EndedSessions::Sso("ref-1"),
        )
        .await;
        for task in tasks {
            assert!(task.await.unwrap());
        }
        let token = transport.calls.lock().unwrap()[0].1.clone();
        let claims = token_claims(&public_key, &token, "c").await;
        assert_eq!(claims["sid"], derive_sid("ref-1", "c"));
    }

    fn other_session() -> SsoSession {
        SsoSession {
            sso_id: "sso-2".into(),
            domain_id: "domain-1".into(),
            user_id: "user-1".into(),
            auth_time: 0,
            amr: vec![],
            upstream: None,
            created_at: 0,
            expires_at: i64::MAX,
        }
    }

    #[tokio::test]
    async fn test_session_logout_spares_rps_without_sid_support_while_other_sessions_exist() {
        let mut required = client("required", Some("https://rp.example.com/bc"));
        required.backchannel_logout_session_required = true;
        let plain = client("plain", Some("https://rp.example.com/bc2"));
        let state = state_with_other_sessions(
            vec!["required", "plain"],
            vec![required, plain],
            Arc::new(Mutex::new(None)),
            vec![other_session()],
        )
        .await;
        let transport = Recorder::new(vec![]);
        let tasks = notify_logout(
            &state,
            transport.clone(),
            fast(),
            "https://k",
            "user-1",
            EndedSessions::Sso("ref-1"),
        )
        .await;
        // Only the RP that matches on `sid` is told; the other one could
        // read the token as "log the user out everywhere".
        assert_eq!(tasks.len(), 1);
        for task in tasks {
            assert!(task.await.unwrap());
        }
        assert_eq!(
            transport.calls.lock().unwrap()[0].0,
            "https://rp.example.com/bc"
        );
    }

    #[tokio::test]
    async fn test_session_logout_tells_every_rp_when_it_was_the_last_session() {
        let state = state_with(
            vec!["a", "b"],
            vec![
                client("a", Some("https://rp.example.com/a")),
                client("b", Some("https://rp.example.com/b")),
            ],
            Arc::new(Mutex::new(None)),
        )
        .await;
        let transport = Recorder::new(vec![]);
        let tasks = notify_logout(
            &state,
            transport.clone(),
            fast(),
            "https://k",
            "user-1",
            EndedSessions::Sso("ref-1"),
        )
        .await;
        assert_eq!(tasks.len(), 2);
    }

    #[tokio::test]
    async fn test_session_required_rp_without_a_session_is_skipped() {
        let mut required = client("device", Some("https://rp.example.com/bc"));
        required.backchannel_logout_session_required = true;
        let optional = client("other", Some("https://rp.example.com/bc2"));
        let public_key = Arc::new(Mutex::new(None));
        let state = state_with(
            vec!["device", "other"],
            vec![required, optional],
            public_key,
        )
        .await;
        let transport = Recorder::new(vec![]);
        let tasks =
            notify_user_logout(&state, transport.clone(), fast(), "https://k", "user-1").await;
        // Only the RP that does not require a `sid` is told.
        assert_eq!(tasks.len(), 1);
        for task in tasks {
            assert!(task.await.unwrap());
        }
        assert_eq!(
            transport.calls.lock().unwrap()[0].0,
            "https://rp.example.com/bc2"
        );
    }

    #[tokio::test]
    async fn test_retries_a_failing_relying_party_then_succeeds() {
        let state = state_with(
            vec!["c"],
            vec![client("c", Some("https://rp.example.com/bc"))],
            Arc::new(Mutex::new(None)),
        )
        .await;
        let transport = Recorder::new(vec![Err("connect".into()), Ok(500), Ok(204)]);
        let tasks =
            notify_user_logout(&state, transport.clone(), fast(), "https://k", "user-1").await;
        assert!(tasks.into_iter().next().unwrap().await.unwrap());
        assert_eq!(transport.calls.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_gives_up_after_the_last_attempt() {
        let state = state_with(
            vec!["c"],
            vec![client("c", Some("https://rp.example.com/bc"))],
            Arc::new(Mutex::new(None)),
        )
        .await;
        let transport = Recorder::new(vec![Ok(500), Ok(500), Ok(500), Ok(500)]);
        let tasks =
            notify_user_logout(&state, transport.clone(), fast(), "https://k", "user-1").await;
        assert!(!tasks.into_iter().next().unwrap().await.unwrap());
        // First attempt plus the two retries.
        assert_eq!(transport.calls.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_disabled_and_deleted_clients_are_skipped() {
        let mut disabled = client("off", Some("https://rp.example.com/bc"));
        disabled.enabled = false;
        let mut deleted = client("gone", Some("https://rp.example.com/bc"));
        deleted.deleted_at = Some(1);
        let state = state_with(
            vec!["off", "gone"],
            vec![disabled, deleted],
            Arc::new(Mutex::new(None)),
        )
        .await;
        let transport = Recorder::new(vec![]);
        let tasks =
            notify_user_logout(&state, transport.clone(), fast(), "https://k", "user-1").await;
        assert!(tasks.is_empty());
        assert!(transport.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_user_without_relying_parties_does_nothing() {
        let state = state_with(vec![], vec![], Arc::new(Mutex::new(None))).await;
        let transport = Recorder::new(vec![]);
        let tasks =
            notify_user_logout(&state, transport.clone(), fast(), "https://k", "user-1").await;
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn test_hook_notifies_on_user_disable_but_not_on_unrelated_events() {
        use openstack_keystone_core_types::events::Operation;
        let mut sessions = MockOauth2SessionProvider::default();
        sessions
            .expect_delete_rp_sessions_by_user()
            .times(1)
            .returning(|_, _| Ok(Vec::new()));
        let mut config = openstack_keystone_config::Config::default();
        config.default.public_endpoint = Some("https://keystone.example.com/".parse().unwrap());
        let state = crate::api::tests::get_mocked_state_with_config(
            Provider::mocked_builder().mock_oauth2_session(sessions),
            true,
            None,
            config,
        )
        .await;
        let hook = BackchannelLogoutHook::new(state);
        let event = |operation, id: &str| Event {
            operation,
            payload: EventPayload::User { id: id.into() },
            timestamp: chrono::Utc::now(),
        };
        hook.on_event(&event(Operation::Disable, "user-1")).await;
        hook.on_event(&event(Operation::Create, "user-1")).await;
        hook.on_event(&event(Operation::Update, "user-1")).await;
    }

    #[tokio::test]
    async fn test_reqwest_transport_refuses_internal_and_plain_http_targets() {
        let transport = ReqwestLogoutTransport;
        for url in [
            "http://rp.example.com/bc",
            "https://127.0.0.1/bc",
            "https://169.254.169.254/latest",
            "https://[::1]/bc",
            "https://10.0.0.5:8443/bc",
        ] {
            assert!(transport.post(url, "t").await.is_err(), "{url}");
        }
    }
}
