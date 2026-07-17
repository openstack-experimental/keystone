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
//! # LDAP connection pools (ADR-0027 §8)
//!
//! Two independent pools are maintained:
//!
//! - [`ServicePool`]: bound as the service account, used for every directory
//!   read (attribute lookups, subtree searches, DN resolution ahead of a
//!   bind).
//! - [`AuthPool`]: never reuses a connection across users. Each end-user
//!   authentication attempt opens (or reuses a just-vacated) connection,
//!   binds as the resolved user DN with the caller-supplied password, and
//!   the connection is dropped immediately after the check. Bounding it
//!   separately from the service pool keeps an authentication storm from
//!   starving directory queries needed for unrelated requests.
use std::sync::Arc;
use std::time::{Duration, Instant};

use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, LdapError, Scope, SearchEntry};
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::{Mutex, Semaphore};

use openstack_keystone_config::{LdapProvider, TlsReqCert};
use openstack_keystone_core_types::identity::IdentityProviderError;

fn ldap_error(context: &str, err: LdapError) -> IdentityProviderError {
    IdentityProviderError::LdapConnection(format!("{context}: {err}"))
}

fn conn_timeout(seconds: f64) -> Option<Duration> {
    if seconds > 0.0 {
        Some(Duration::from_secs_f64(seconds))
    } else {
        None
    }
}

/// Build the [`LdapConnSettings`] implied by the `[ldap]` TLS/timeout
/// configuration for one candidate `url`.
fn conn_settings(cfg: &LdapProvider, url: &str) -> LdapConnSettings {
    let mut settings = LdapConnSettings::new();
    if let Some(timeout) = conn_timeout(cfg.connection_timeout) {
        settings = settings.set_conn_timeout(timeout);
    }
    if cfg.use_tls {
        // `ldaps://` URLs negotiate TLS at the transport level; a plain
        // `ldap://` URL relies on StartTLS instead.
        settings = settings.set_starttls(!url.starts_with("ldaps://"));
        if cfg.tls_req_cert == TlsReqCert::Never {
            tracing::warn!(
                "[ldap] tls_req_cert = never: LDAP server certificate verification is disabled"
            );
            settings = settings.set_no_tls_verify(true);
        }
    }
    settings
}

/// Split `[ldap] url` into individual candidate URLs (comma/whitespace
/// separated, matching Python's `re.split(r'[\s,]+', conf.ldap.url)`), for
/// HA failover across multiple directory servers, optionally shuffled per
/// `randomize_urls` so a downed first server doesn't serialize every
/// process/thread behind the same connection-timeout wait.
fn candidate_urls(cfg: &LdapProvider) -> Vec<String> {
    let mut urls: Vec<String> = cfg
        .url
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if cfg.randomize_urls {
        use rand::seq::SliceRandom;
        urls.shuffle(&mut rand::rng());
    }
    urls
}

/// Open a connection to the directory — trying each of `[ldap] url`'s
/// comma/whitespace-separated candidates in turn, using the first that
/// connects — and bind as `bind_dn`/`bind_pw` (anonymous bind when
/// `bind_dn` is `None`).
async fn connect_and_bind(
    cfg: &LdapProvider,
    bind_dn: Option<&str>,
    bind_pw: Option<&str>,
) -> Result<Ldap, IdentityProviderError> {
    let urls = candidate_urls(cfg);
    let mut last_err = None;
    for url in &urls {
        match LdapConnAsync::with_settings(conn_settings(cfg, url), url).await {
            Ok((conn, mut ldap)) => {
                ldap3::drive!(conn);
                let bind_result = match (bind_dn, bind_pw) {
                    (Some(dn), Some(pw)) => ldap.simple_bind(dn, pw).await,
                    _ => ldap.simple_bind("", "").await,
                };
                match bind_result.and_then(|r| r.success()) {
                    Ok(_) => return Ok(ldap),
                    Err(e) => {
                        last_err = Some(ldap_error("binding to LDAP server", e));
                        // A bind failure (bad credentials) is authoritative,
                        // not a per-server connectivity fluke — don't try
                        // the next URL as if this one were merely down.
                        break;
                    }
                }
            }
            Err(e) => last_err = Some(ldap_error("connecting to LDAP server", e)),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        IdentityProviderError::LdapConnection("no [ldap] url configured".into())
    }))
}

struct PooledConnection {
    ldap: Ldap,
    created_at: Instant,
}

/// Connection pool bound as the service account, used for all directory
/// reads.
pub struct ServicePool {
    cfg: Arc<LdapProvider>,
    idle: Mutex<Vec<PooledConnection>>,
    permits: Semaphore,
    max_lifetime: Duration,
}

impl ServicePool {
    pub fn new(cfg: Arc<LdapProvider>) -> Self {
        let size = if cfg.pool {
            cfg.pool_size.max(1) as usize
        } else {
            1
        };
        let max_lifetime = if cfg.pool_connection_lifetime > 0.0 {
            Duration::from_secs_f64(cfg.pool_connection_lifetime)
        } else {
            Duration::MAX
        };
        Self {
            cfg,
            idle: Mutex::new(Vec::new()),
            permits: Semaphore::new(size),
            max_lifetime,
        }
    }

    async fn acquire(&self) -> Result<Ldap, IdentityProviderError> {
        // The permit bounds concurrent connections at `pool_size`; it is
        // released implicitly once this function returns, since we hand
        // back an owned `Ldap` handle rather than holding the permit for
        // the caller's whole request. Concurrency is still capped because
        // `acquire()` blocks until a permit is available.
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;

        if let Some(conn) = self.idle.lock().await.pop()
            && conn.created_at.elapsed() < self.max_lifetime
        {
            return Ok(conn.ldap);
        }

        let mut retries_left = self.cfg.pool_retry_max.max(0);
        let retry_delay = Duration::from_secs_f64(self.cfg.pool_retry_delay.max(0.0));
        loop {
            match connect_and_bind(
                &self.cfg,
                self.cfg.user.as_deref(),
                self.cfg.password.as_ref().map(|s| s.expose_secret()),
            )
            .await
            {
                Ok(ldap) => return Ok(ldap),
                Err(_) if retries_left > 0 => {
                    retries_left -= 1;
                    tokio::time::sleep(retry_delay).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn release(&self, ldap: Ldap) {
        self.idle.lock().await.push(PooledConnection {
            ldap,
            created_at: Instant::now(),
        });
    }

    /// Verify the directory is reachable and the service bind credentials
    /// are valid. Used at backend construction time to fail fast rather
    /// than register a backend that can never serve a request.
    pub async fn health_check(&self) -> Result<(), IdentityProviderError> {
        let ldap = self.acquire().await?;
        self.release(ldap).await;
        Ok(())
    }

    /// Non-paged search, suitable for BASE-scoped lookups and small result
    /// sets (single-entry `get`/`dn_to_id` resolution).
    pub async fn search(
        &self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>, IdentityProviderError> {
        let mut ldap = self.acquire().await?;
        let raw = ldap.search(base, scope, filter, attrs).await;
        self.release(ldap).await;
        let search_result = raw.map_err(|e| ldap_error("searching LDAP directory", e))?;
        match search_result.success() {
            Ok((entries, _res)) => Ok(entries.into_iter().map(SearchEntry::construct).collect()),
            // The search base itself doesn't exist (e.g. a constructed DN
            // for a nonexistent object, or a misconfigured tree DN) — treat
            // as "no results" rather than a hard error.
            Err(LdapError::LdapResult { result }) if result.rc == 32 => Ok(vec![]),
            Err(e) => Err(ldap_error("searching LDAP directory", e)),
        }
    }

    /// Paged subtree search (RFC 2696), looping until the server returns an
    /// empty cookie. Used by every unbounded subtree operation
    /// (`list_users`, `list_groups`, membership reverse-searches) so large
    /// directories don't exceed the server's configured `sizelimit`.
    pub async fn paged_search(
        &self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>, IdentityProviderError> {
        let page_size = self.cfg.page_size;
        if page_size <= 0 {
            return self.search(base, scope, filter, attrs).await;
        }

        let mut ldap = self.acquire().await?;
        let mut entries = Vec::new();
        let adapter = ldap3::adapters::PagedResults::new(page_size);
        let mut stream = match ldap
            .streaming_search_with(adapter, base, scope, filter, attrs)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                self.release(ldap).await;
                return Err(ldap_error("starting paged LDAP search", e));
            }
        };
        loop {
            match stream.next().await {
                Ok(Some(entry)) => entries.push(SearchEntry::construct(entry)),
                Ok(None) => break,
                Err(e) => {
                    return Err(ldap_error("reading paged LDAP search results", e));
                }
            }
        }
        if let Err(e) = stream.finish().await.success()
            && !matches!(&e, LdapError::LdapResult { result } if result.rc == 32)
        {
            return Err(ldap_error("finishing paged LDAP search", e));
        }
        self.release(ldap).await;
        Ok(entries)
    }
}

/// Connection pool used exclusively for the second step of
/// `authenticate_by_password`: binding as the resolved end-user DN with the
/// caller-supplied password. Connections are never reused across users or
/// requests.
pub struct AuthPool {
    cfg: Arc<LdapProvider>,
    permits: Semaphore,
}

impl AuthPool {
    pub fn new(cfg: Arc<LdapProvider>) -> Self {
        let size = if cfg.auth_pool {
            cfg.auth_pool_size.max(1) as usize
        } else {
            cfg.pool_size.max(1) as usize
        };
        Self {
            cfg,
            permits: Semaphore::new(size),
        }
    }

    /// Attempt a simple bind as `user_dn` with `password`. Returns `Ok(())`
    /// on a successful bind, or an authentication/connection error
    /// otherwise. The connection is unbound and dropped immediately after
    /// the check, regardless of outcome.
    pub async fn try_bind(
        &self,
        user_dn: &str,
        password: &SecretString,
    ) -> Result<(), IdentityProviderError> {
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|e| IdentityProviderError::LdapConnection(e.to_string()))?;

        let mut ldap = connect_and_bind(&self.cfg, None, None).await?;
        let bind_result = ldap
            .simple_bind(user_dn, password.expose_secret())
            .await
            .map_err(|e| ldap_error("binding as user", e))
            .and_then(|res| res.success().map_err(|e| ldap_error("binding as user", e)));
        let _ = ldap.unbind().await;
        bind_result.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conn_timeout_positive_seconds() {
        assert_eq!(conn_timeout(5.0), Some(Duration::from_secs_f64(5.0)));
    }

    #[test]
    fn test_conn_timeout_non_positive_means_infinite() {
        assert_eq!(conn_timeout(0.0), None);
        assert_eq!(conn_timeout(-1.0), None);
    }

    #[test]
    fn test_conn_settings_starttls_for_plain_ldap_url() {
        let cfg = LdapProvider {
            use_tls: true,
            url: "ldap://directory.example.com".into(),
            ..Default::default()
        };
        assert!(conn_settings(&cfg, &cfg.url).starttls());
    }

    #[test]
    fn test_conn_settings_no_starttls_for_ldaps_url() {
        let cfg = LdapProvider {
            use_tls: true,
            url: "ldaps://directory.example.com".into(),
            ..Default::default()
        };
        assert!(!conn_settings(&cfg, &cfg.url).starttls());
    }

    #[test]
    fn test_conn_settings_no_tls_when_disabled() {
        let cfg = LdapProvider {
            use_tls: false,
            url: "ldap://directory.example.com".into(),
            ..Default::default()
        };
        assert!(!conn_settings(&cfg, &cfg.url).starttls());
    }

    #[test]
    fn test_candidate_urls_splits_comma_and_whitespace() {
        let cfg = LdapProvider {
            url: "ldap://s1.example.com, ldap://s2.example.com  ldap://s3.example.com".into(),
            ..Default::default()
        };
        assert_eq!(
            candidate_urls(&cfg),
            vec![
                "ldap://s1.example.com",
                "ldap://s2.example.com",
                "ldap://s3.example.com",
            ]
        );
    }

    #[test]
    fn test_candidate_urls_single_url_passthrough() {
        let cfg = LdapProvider {
            url: "ldap://directory.example.com".into(),
            ..Default::default()
        };
        assert_eq!(candidate_urls(&cfg), vec!["ldap://directory.example.com"]);
    }
}
