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
//! Common functionality used in the functional tests.

use eyre::{OptionExt, Result, WrapErr, eyre};
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};
use reqwest::{
    Client, ClientBuilder, Response, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use secrecy::{ExposeSecret, SecretString};
use std::env;
use std::sync::Arc;
use url::Url;

use openstack_keystone_api_types::scope::{
    DomainBuilder, Scope, ScopeProjectBuilder, System as ScopeSystem,
};
use openstack_keystone_api_types::v3::auth::token::*;

async fn authentication_error(rsp: Response) -> eyre::Report {
    let status = rsp.status();

    let request_id = rsp
        .headers()
        .get("x-openstack-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    let body = rsp.text().await.unwrap_or_default();

    match (request_id, body.is_empty()) {
        (Some(request_id), false) => {
            eyre!("Authentication failed with {status}, request-id: {request_id}: {body}")
        }
        (Some(request_id), true) => {
            eyre!("Authentication failed with {status}, request-id: {request_id}")
        }
        (None, false) => eyre!("Authentication failed with {status}: {body}"),
        (None, true) => eyre!("Authentication failed with {status}"),
    }
}

pub struct TestClient {
    pub client: Client,
    pub base_url: Url,
    pub auth: Option<TokenResponse>,
    pub token: Option<SecretString>,
}

impl TestClient {
    pub fn default() -> Result<Self> {
        Ok(Self {
            client: Client::new(),
            base_url: env::var("KEYSTONE_URL")
                .wrap_err("KEYSTONE_URL must be set")?
                .parse()?,
            auth: None,
            token: None,
        })
    }

    pub async fn auth(&mut self, identity: Identity, scope: Option<Scope>) -> Result<&mut Self> {
        self.authenticate(identity, scope).await
    }

    /// Shared authentication flow: POST the auth request to
    /// `v3/auth/tokens`, extract the subject token and rebuild the inner
    /// client with the `x-auth-token` default header. Used by both initial
    /// authentication ([`Self::auth`]) and token rescoping
    /// ([`Self::rescope`]).
    async fn authenticate(
        &mut self,
        identity: Identity,
        scope: Option<Scope>,
    ) -> Result<&mut Self> {
        let new = self;
        let auth_request = AuthRequest {
            auth: AuthRequestInner { identity, scope },
        };
        let rsp = new
            .client
            .post(new.base_url.join("v3/auth/tokens")?)
            .json(&serde_json::to_value(auth_request)?)
            .send()
            .await?;

        if rsp.status() != StatusCode::CREATED {
            return Err(authentication_error(rsp).await);
        }

        let token = rsp
            .headers()
            .get("X-Subject-Token")
            .ok_or_else(|| eyre!("Token is missing in the {:?}", rsp))?
            .to_str()?
            .to_string();

        new.token = Some(SecretString::from(token.clone()));
        new.auth = Some(rsp.json().await?);
        let mut token = HeaderValue::from_str(&token)?;
        token.set_sensitive(true);
        new.client = ClientBuilder::new()
            .default_headers(HeaderMap::from_iter([(
                HeaderName::from_static("x-auth-token"),
                token,
            )]))
            .build()?;
        Ok(new)
    }

    /// Authenticate using the passed password auth and the scope.
    pub async fn auth_password(
        &mut self,
        password_auth: PasswordAuth,
        scope: Option<Scope>,
    ) -> Result<&mut Self> {
        let new = self;
        let identity = IdentityBuilder::default()
            .methods(vec!["password".into()])
            .password(password_auth)
            .build()?;
        new.auth(identity, scope).await?;
        Ok(new)
    }

    pub async fn auth_admin(&mut self) -> Result<&mut Self> {
        let new = self;
        new.auth_password(
            get_password_auth(
                "admin",
                env::var("OPENSTACK_ADMIN_PASSWORD").unwrap_or("password".to_string()),
                "default",
            )?,
            Some(Scope::Project(
                ScopeProjectBuilder::default()
                    .name("admin")
                    .domain(DomainBuilder::default().id("default").build()?)
                    .build()?,
            )),
        )
        .await?;
        Ok(new)
    }

    pub async fn auth_admin_system(&mut self) -> Result<&mut Self> {
        let new = self;
        new.auth_password(
            get_password_auth(
                "admin",
                env::var("OPENSTACK_ADMIN_PASSWORD").unwrap_or("password".to_string()),
                "default",
            )?,
            Some(Scope::System(ScopeSystem { all: Some(true) })),
        )
        .await?;
        Ok(new)
    }

    pub async fn auth_domain(&mut self, domain_id: &str) -> Result<&mut Self> {
        let new = self;
        new.rescope(Some(Scope::Domain(
            DomainBuilder::default().id(domain_id).build()?,
        )))
        .await?;
        Ok(new)
    }

    pub async fn auth_token<S>(&mut self, token: S, scope: Option<Scope>) -> Result<&mut Self>
    where
        S: AsRef<str> + std::fmt::Display,
    {
        let new = self;
        let identity = IdentityBuilder::default()
            .methods(vec!["token".into()])
            .token(TokenAuthBuilder::default().id(token.as_ref()).build()?)
            .build()?;
        new.auth(identity, scope).await?;
        Ok(new)
    }

    /// Rescope the stored token to a new scope via token authentication.
    pub async fn rescope(&mut self, scope: Option<Scope>) -> Result<&mut Self> {
        let new = self;

        let identity = IdentityBuilder::default()
            .methods(vec!["token".into()])
            .token(
                TokenAuthBuilder::default()
                    .id(new
                        .token
                        .as_ref()
                        .ok_or_eyre("must be authenticated")?
                        .expose_secret())
                    .build()?,
            )
            .build()?;

        new.authenticate(identity, scope).await
    }
}

/// Get the password auth identity struct
pub fn get_password_auth<U, P, DID>(
    username: U,
    password: P,
    domain_id: DID,
) -> Result<PasswordAuth>
where
    U: AsRef<str>,
    P: AsRef<str>,
    DID: AsRef<str>,
{
    PasswordAuthBuilder::default()
        .user(
            UserPasswordBuilder::default()
                .name(username.as_ref())
                .password(password.as_ref())
                .domain(DomainBuilder::default().id(domain_id.as_ref()).build()?)
                .build()?,
        )
        .build()
        .map_err(Into::into)
}

/// Test user authentication with name and password.
///
/// The openstack_sdk currently does heavy caching so that bypassing it on the
/// regular interface is not possible. We need to ensure the call is done to
/// verify the user password.
pub async fn auth_user_by_password<U: AsRef<str>, D: AsRef<str>, P: AsRef<str>>(
    username: U,
    domain_id: D,
    password: P,
) -> Result<()> {
    let password_auth = get_password_auth(username, password, domain_id)?;
    let identity = IdentityBuilder::default()
        .methods(vec!["password".into()])
        .password(password_auth)
        .build()?;
    let auth_request = AuthRequest {
        auth: AuthRequestInner {
            identity,
            scope: None,
        },
    };

    let base_url: Url = env::var("KEYSTONE_URL")
        .wrap_err("KEYSTONE_URL must be set")?
        .parse()?;

    let rsp = Client::new()
        .post(base_url.join("v3/auth/tokens")?)
        .json(&serde_json::to_value(auth_request)?)
        .send()
        .await?;

    if !rsp.status().is_success() {
        return Err(authentication_error(rsp).await);
    }
    Ok(())
}

/// Get AsyncOpenStack session for user by name, domain and password.
pub async fn get_session_by_user_password<U: AsRef<str>, D: AsRef<str>, P: AsRef<str>>(
    username: U,
    domain_id: D,
    password: P,
) -> Result<Arc<AsyncOpenStack>> {
    let config = CloudConfig {
        auth: Some(openstack_sdk::config::Auth {
            auth_url: Some(env::var("OS_AUTH_URL")?),
            username: Some(username.as_ref().to_string()),
            user_domain_id: Some(domain_id.as_ref().to_string()),
            password: Some(password.as_ref().into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    Ok(Arc::new(AsyncOpenStack::new(&config).await?))
}

/// Get AsyncOpenStack session system scope
pub async fn get_system_scope_session() -> Result<Arc<AsyncOpenStack>> {
    let mut test_client = AsyncOpenStack::new(&CloudConfig::from_env()?).await?;
    test_client
        .authorize(
            Some(openstack_sdk::auth::authtoken::AuthTokenScope::System(
                openstack_sdk::types::identity::v3::System { all: Some(true) },
            )),
            false,
            false,
        )
        .await?;
    Ok(Arc::new(test_client))
}

/// Base credentials from the environment (`OS_*` variables via
/// [`CloudConfig::from_env`]). The deployment-specific admin
/// username/password/user-domain are preserved as-is (Kubernetes and
/// non-default environments configure these differently); only the scope
/// fields are replaced by the requested scope.
fn env_auth() -> Result<openstack_sdk::config::Auth> {
    CloudConfig::from_env()?
        .auth
        .ok_or_eyre("auth section must be configured in the environment")
}

/// Clear every scope field, leaving only the credential fields.
fn clear_scope(auth: &mut openstack_sdk::config::Auth) {
    auth.project_id = None;
    auth.project_name = None;
    auth.project_domain_id = None;
    auth.project_domain_name = None;
    auth.domain_id = None;
    auth.domain_name = None;
    auth.system_scope = None;
}

/// Pure constructor: replace whatever scope `auth` carries with `scope`,
/// keeping the credential fields untouched.
fn rescope_config(mut auth: openstack_sdk::config::Auth, scope: &Scope) -> CloudConfig {
    clear_scope(&mut auth);
    apply_scope(&mut auth, scope);
    CloudConfig {
        auth: Some(auth),
        ..Default::default()
    }
}

/// Pure constructor: credentials for an arbitrary user with an optional
/// scope.
fn user_config(
    auth_url: String,
    name: &str,
    password: &str,
    user_domain_id: &str,
    scope: Option<&Scope>,
) -> CloudConfig {
    let mut auth = openstack_sdk::config::Auth {
        auth_url: Some(auth_url),
        username: Some(name.to_string()),
        user_domain_id: Some(user_domain_id.to_string()),
        password: Some(password.into()),
        ..Default::default()
    };
    if let Some(scope) = scope {
        apply_scope(&mut auth, scope);
    }
    CloudConfig {
        auth: Some(auth),
        ..Default::default()
    }
}

/// [`CloudConfig`] for the environment's admin scoped to the given domain.
///
/// Domain- and project-scoped credentials are subject to scope isolation:
/// they must not be able to list or access resources outside their scope
/// (enforced by the OPA policies, e.g. `domain_matches_domain_scope`).
pub fn get_domain_scope_config(domain_id: &str) -> Result<CloudConfig> {
    Ok(rescope_config(
        env_auth()?,
        &Scope::Domain(DomainBuilder::default().id(domain_id).build()?),
    ))
}

/// [`CloudConfig`] for the environment's admin scoped to the given project.
///
/// `project_domain_id` is the ID of the domain the project belongs to.
pub fn get_project_scope_config(project_id: &str, project_domain_id: &str) -> Result<CloudConfig> {
    Ok(rescope_config(
        env_auth()?,
        &Scope::Project(
            ScopeProjectBuilder::default()
                .id(project_id)
                .domain(DomainBuilder::default().id(project_domain_id).build()?)
                .build()?,
        ),
    ))
}

/// [`CloudConfig`] for an arbitrary (typically non-admin) user with an
/// optional scope. With `scope: None` the resulting session holds an
/// unscoped token.
///
/// The returned config is not authenticated yet — pass it to
/// [`session_for_config`] (or `AsyncOpenStack::new`) to obtain a live
/// session and surface authentication/authorization errors.
pub fn config_for_user(
    name: &str,
    password: &str,
    user_domain_id: &str,
    scope: Option<&Scope>,
) -> Result<CloudConfig> {
    let auth_url = env_auth()?
        .auth_url
        .ok_or_eyre("auth_url must be configured in the environment")?;
    Ok(user_config(auth_url, name, password, user_domain_id, scope))
}

/// Map an API [`Scope`] onto the scope fields of a config `Auth` block.
///
/// - `Scope::Project` sets `project_id`/`project_name` and the project's
///   domain,
/// - `Scope::Domain` sets `domain_id`/`domain_name` (a genuinely
///   *domain*-scoped token; note that policy `domain_matches_domain_scope`
///   checks only pass for this scope, never for a project scope in the same
///   domain),
/// - `Scope::System` sets `system_scope=all`,
/// - `Scope::Unscoped` leaves all scope fields unset.
fn apply_scope(auth: &mut openstack_sdk::config::Auth, scope: &Scope) {
    match scope {
        Scope::Project(project) => {
            auth.project_id = project.id.clone();
            auth.project_name = project.name.clone();
            if let Some(domain) = &project.domain {
                auth.project_domain_id = domain.id.clone();
                auth.project_domain_name = domain.name.clone();
            }
        }
        Scope::Domain(domain) => {
            auth.domain_id = domain.id.clone();
            auth.domain_name = domain.name.clone();
        }
        Scope::System(_) => {
            auth.system_scope = Some("all".to_string());
        }
        Scope::Unscoped => {}
    }
}

/// Authenticate the given [`CloudConfig`] and return a live session.
pub async fn session_for_config(config: &CloudConfig) -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(AsyncOpenStack::new(config).await?))
}

/// Admin session scoped to the given domain (see [`get_domain_scope_config`]).
pub async fn get_domain_scope_session(domain_id: &str) -> Result<Arc<AsyncOpenStack>> {
    session_for_config(&get_domain_scope_config(domain_id)?).await
}

/// Admin session scoped to the given project (see
/// [`get_project_scope_config`]).
pub async fn get_project_scope_session(
    project_id: &str,
    project_domain_id: &str,
) -> Result<Arc<AsyncOpenStack>> {
    session_for_config(&get_project_scope_config(project_id, project_domain_id)?).await
}

/// Session for an arbitrary user with an optional scope (see
/// [`config_for_user`]).
pub async fn get_user_session(
    name: &str,
    password: &str,
    user_domain_id: &str,
    scope: Option<&Scope>,
) -> Result<Arc<AsyncOpenStack>> {
    session_for_config(&config_for_user(name, password, user_domain_id, scope)?).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH_URL: &str = "http://localhost:8080";

    /// A base auth block as a K8s/non-default environment might provide
    /// it: custom admin name, custom user domain, project-scoped.
    fn base_auth() -> openstack_sdk::config::Auth {
        openstack_sdk::config::Auth {
            auth_url: Some(AUTH_URL.to_string()),
            username: Some("cluster-admin".to_string()),
            user_domain_id: Some("admin-domain".to_string()),
            password: Some("secret".into()),
            project_name: Some("admin".to_string()),
            project_domain_id: Some("admin-domain".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn rescope_to_domain_replaces_scope_keeps_credentials() -> Result<()> {
        let config = rescope_config(
            base_auth(),
            &Scope::Domain(DomainBuilder::default().id("did").build()?),
        );
        let auth = config.auth.ok_or_eyre("auth must be set")?;
        assert_eq!(auth.domain_id.as_deref(), Some("did"));
        assert_eq!(auth.username.as_deref(), Some("cluster-admin"));
        assert_eq!(auth.user_domain_id.as_deref(), Some("admin-domain"));
        assert!(auth.project_id.is_none(), "prior project scope must go");
        assert!(auth.project_name.is_none(), "prior project scope must go");
        assert!(auth.system_scope.is_none(), "no system scope expected");
        Ok(())
    }

    #[test]
    fn rescope_to_project_replaces_scope() -> Result<()> {
        let config = rescope_config(
            base_auth(),
            &Scope::Project(
                ScopeProjectBuilder::default()
                    .id("pid")
                    .domain(DomainBuilder::default().id("did").build()?)
                    .build()?,
            ),
        );
        let auth = config.auth.ok_or_eyre("auth must be set")?;
        assert_eq!(auth.project_id.as_deref(), Some("pid"));
        assert_eq!(auth.project_domain_id.as_deref(), Some("did"));
        assert!(
            auth.project_name.is_none(),
            "prior project-name scope must go"
        );
        assert!(auth.domain_id.is_none(), "no domain scope expected");
        assert!(auth.system_scope.is_none(), "no system scope expected");
        Ok(())
    }

    #[test]
    fn user_config_unscoped_leaves_scope_unset() -> Result<()> {
        let config = user_config(AUTH_URL.to_string(), "alice", "secret", "did", None);
        let auth = config.auth.ok_or_eyre("auth must be set")?;
        assert_eq!(auth.auth_url.as_deref(), Some(AUTH_URL));
        assert_eq!(auth.username.as_deref(), Some("alice"));
        assert_eq!(auth.user_domain_id.as_deref(), Some("did"));
        assert!(auth.project_id.is_none(), "unscoped: no project fields");
        assert!(auth.domain_id.is_none(), "unscoped: no domain fields");
        assert!(auth.system_scope.is_none(), "unscoped: no system fields");
        Ok(())
    }

    #[test]
    fn user_config_project_scope_maps_all_fields() -> Result<()> {
        let scope = Scope::Project(
            ScopeProjectBuilder::default()
                .id("pid")
                .domain(DomainBuilder::default().id("pdid").build()?)
                .build()?,
        );
        let config = user_config(AUTH_URL.to_string(), "alice", "secret", "did", Some(&scope));
        let auth = config.auth.ok_or_eyre("auth must be set")?;
        assert_eq!(auth.project_id.as_deref(), Some("pid"));
        assert_eq!(auth.project_domain_id.as_deref(), Some("pdid"));
        assert!(auth.domain_id.is_none(), "no domain scope expected");
        Ok(())
    }

    #[test]
    fn user_config_system_scope_sets_system_all() -> Result<()> {
        let scope = Scope::System(ScopeSystem { all: Some(true) });
        let config = user_config(AUTH_URL.to_string(), "alice", "secret", "did", Some(&scope));
        let auth = config.auth.ok_or_eyre("auth must be set")?;
        assert_eq!(auth.system_scope.as_deref(), Some("all"));
        assert!(auth.project_id.is_none(), "no project scope expected");
        assert!(auth.domain_id.is_none(), "no domain scope expected");
        Ok(())
    }
}
