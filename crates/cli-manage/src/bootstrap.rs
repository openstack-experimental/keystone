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
//! Bootstrap Keystone data for keystone-manage.

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{eyre::WrapErr, eyre::eyre};
use eyre::Result;
use reqwest::{Client, StatusCode, Url};
use serde_json::json;
use spiffe_rustls::{authorizer, mtls_client};
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    prelude::*,
};

use openstack_keystone_api_types::v3::domain::*;
use openstack_keystone_api_types::v3::project::*;
use openstack_keystone_api_types::v3::role::*;
use openstack_keystone_api_types::v3::user::*;
use openstack_keystone_config::Config;

use crate::PerformAction;

/// Bootstrap Keystone data.
#[derive(Parser)]
pub struct BootstrapCommand {
    /// Bootstrap project name.
    #[arg(long, default_value = "admin", env = "OS_BOOTSTRAP_PROJECT_NAME")]
    bootstrap_project_name: String,

    /// Bootstrap user password.
    #[arg(long, env = "OS_BOOTSTRAP_PASSWORD")]
    bootstrap_password: String,

    /// Bootstrap user name.
    #[arg(long, default_value = "admin", env = "OS_BOOTSTRAP_USERNAME")]
    bootstrap_username: String,

    /// Verbosity level. Repeat to increase level.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn setup_logging(verbose: u8) {
    let filter = Targets::new().with_default(match verbose {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    });

    let log_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(filter);

    let _ = tracing::subscriber::set_global_default(tracing_subscriber::registry().with(log_layer));
}

#[async_trait]
impl PerformAction for BootstrapCommand {
    async fn take_action(self, config: &Config) -> Result<()> {
        setup_logging(self.verbose);

        // Validate password (may come from --bootstrap-password or
        // OS_BOOTSTRAP_PASSWORD)
        if self.bootstrap_password.is_empty() {
            return Err(eyre!("--bootstrap-password must not be empty"));
        }

        if let Some(admin_if) = &config.interface_admin {
            let ks_admin_socket = admin_if.listener.socket_path.clone();

            // Fetch X.509 SVID dynamically from SPIFFE
            let source = spiffe::X509Source::new().await?;

            // Build mTLS ClientConfig with SPIFFE SVID
            let client_config = mtls_client(source.clone())
                .authorize(authorizer::any())
                .build()
                .wrap_err("Building SPIFFE mTLS client config failed")?;

            // Create reqwest client with UDS + SPIFFE mTLS
            let client = Client::builder()
                .unix_socket(ks_admin_socket.clone())
                .tls_backend_preconfigured(client_config)
                .build()
                .wrap_err("Building reqwest client failed")?;

            self.bootstrap_with_client(
                &client,
                config,
                "https://localhost",
                &self.bootstrap_password,
            )
            .await?;

            println!("Bootstrap complete:");
            println!("  admin user:    {}", self.bootstrap_username);
            println!("  admin project: {}", self.bootstrap_project_name);
            println!("  admin domain:  {}", config.identity.default_domain_id);
            println!("  roles:         admin, manager, member, reader");

            Ok(())
        } else {
            return Err(eyre!(
                "admin interface not configured; bootstrap requires [interface_admin]"
            ));
        }
    }
}

impl BootstrapCommand {
    /// Execute the full bootstrap flow against a pre-built HTTP client.
    ///
    /// `base_url` is the API base URL (without trailing slash) that the
    /// client will connect to. In production the client is built with a Unix
    /// socket so `base_url` is `"https://localhost"`; in tests it points to
    /// the mock server.
    ///
    /// This is the public entry point for tests that inject a mock client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn bootstrap_with_client(
        &self,
        client: &Client,
        config: &Config,
        base_url: &str,
        password: &str,
    ) -> Result<()> {
        self.bootstrap_domain(client, config, base_url).await?;
        let project = self.bootstrap_project(client, config, base_url).await?;
        let user = self
            .bootstrap_user(client, config, base_url, password)
            .await?;
        let admin_role = self.upsert_role(client, config, "admin", base_url).await?;
        let manager_role = self
            .upsert_role(client, config, "manager", base_url)
            .await?;
        let member_role = self.upsert_role(client, config, "member", base_url).await?;
        let reader_role = self.upsert_role(client, config, "reader", base_url).await?;
        self.upsert_implied_role(client, &admin_role, &manager_role, base_url)
            .await?;
        self.upsert_implied_role(client, &manager_role, &member_role, base_url)
            .await?;
        self.upsert_implied_role(client, &member_role, &reader_role, base_url)
            .await?;
        self.upsert_user_role_project(client, &user, &project, &admin_role, base_url)
            .await?;
        self.upsert_user_role_system(client, &user, &admin_role, base_url)
            .await?;

        Ok(())
    }

    /// Bootstrap the default domain.
    async fn bootstrap_domain(
        &self,
        client: &Client,
        config: &Config,
        base_url: &str,
    ) -> Result<()> {
        let res = client
            .post(format!("{base_url}/v3/domains"))
            .json(&DomainCreateRequest {
                domain: DomainCreateBuilder::default()
                    .description("The default domain")
                    .name("default")
                    .id(config.identity.default_domain_id.clone())
                    .enabled(true)
                    .build()?,
            })
            .send()
            .await
            .wrap_err("creating default domain failed")?;
        match res.status() {
            StatusCode::CREATED | StatusCode::NO_CONTENT => Ok(()),
            StatusCode::CONFLICT => Ok(()), // domain already exists
            status => Err(eyre!(
                "failed to create default domain: {} ({})",
                status,
                res.text().await.unwrap_or_default()
            )),
        }
    }

    /// Bootstrap the default project.
    async fn bootstrap_project(
        &self,
        client: &Client,
        config: &Config,
        base_url: &str,
    ) -> Result<Project> {
        // Check if the project already exists
        let existing_projects = client
            .get(Url::parse_with_params(
                &format!("{base_url}/v3/projects"),
                &[
                    ("name", self.bootstrap_project_name.as_str()),
                    ("domain_id", config.identity.default_domain_id.as_str()),
                ],
            )?)
            .send()
            .await
            .wrap_err("listing projects to check for existing bootstrap project failed")?
            .json::<openstack_keystone_api_types::v3::project::ProjectShortList>()
            .await?
            .projects;

        if let Some(existing) = existing_projects.first() {
            // Project exists — fetch the full representation
            Ok(client
                .get(format!("{base_url}/v3/projects/{}", existing.id))
                .send()
                .await
                .wrap_err("fetching existing bootstrap project failed")?
                .json::<ProjectResponse>()
                .await?
                .project)
        } else {
            let res = client
                .post(format!("{base_url}/v3/projects"))
                .json(&ProjectCreateRequest {
                    project: ProjectCreateBuilder::default()
                        .description("Bootstrap project for initializing the cloud.")
                        .name(self.bootstrap_project_name.clone())
                        .domain_id(config.identity.default_domain_id.clone())
                        .enabled(true)
                        .build()?,
                })
                .send()
                .await
                .wrap_err("creating default project failed")?;
            if res.status() == StatusCode::CONFLICT {
                // Project was created concurrently; fetch it by name
                let projects = client
                    .get(Url::parse_with_params(
                        &format!("{base_url}/v3/projects"),
                        &[
                            ("name", self.bootstrap_project_name.as_str()),
                            ("domain_id", config.identity.default_domain_id.as_str()),
                        ],
                    )?)
                    .send()
                    .await?
                    .json::<openstack_keystone_api_types::v3::project::ProjectShortList>()
                    .await?
                    .projects;
                let proj = projects.first().ok_or_else(|| {
                    eyre!("bootstrap project not found after concurrent creation")
                })?;
                Ok(client
                    .get(format!("{base_url}/v3/projects/{}", proj.id))
                    .send()
                    .await?
                    .json::<ProjectResponse>()
                    .await?
                    .project)
            } else {
                Ok(res.json::<ProjectResponse>().await?.project)
            }
        }
    }

    /// Bootstrap the default user.
    ///
    /// If the user already exists, ensure it is enabled and the password
    /// matches.
    async fn bootstrap_user(
        &self,
        client: &Client,
        config: &Config,
        base_url: &str,
        password: &str,
    ) -> Result<User> {
        // Find the existing user
        let url = format!("{base_url}/v3/users");
        let existing_matching_users = client
            .get(Url::parse_with_params(
                &url,
                &[
                    ("domain_id", config.identity.default_domain_id.clone()),
                    ("name", self.bootstrap_username.clone()),
                ],
            )?)
            .send()
            .await?
            .json::<UserList>()
            .await?
            .users;

        if let Some(existing_user) = existing_matching_users.first() {
            // User exists — ensure it is enabled and the password is correct.
            let user = if !existing_user.enabled {
                client
                    .put(format!("{base_url}/v3/users/{}", existing_user.id))
                    .json(&UserUpdateRequest {
                        user: UserUpdateBuilder::default()
                            .enabled(true)
                            .password(password.to_string())
                            .build()?,
                    })
                    .send()
                    .await
                    .wrap_err("updating existing user failed")?
                    .json::<UserResponse>()
                    .await?
                    .user
            } else {
                existing_user.clone()
            };

            // Verify the password works
            let res = client
                .post(format!("{base_url}/v3/auth/tokens"))
                .json(&json!({
                    "auth": {
                        "identity": {
                            "methods": ["password"],
                            "password": {
                                "user": {
                                    "id": existing_user.id.clone(),
                                    "password": password
                                }
                            }
                        }
                    }
                }))
                .send()
                .await
                .wrap_err(
                    "password authentication failed for existing user \
                     (run with a matching --bootstrap-password or reset the user)",
                )?;
            if !res.status().is_success() {
                return Err(eyre!(
                    "password authentication failed for existing user: {} ({})",
                    res.status(),
                    res.text().await.unwrap_or_default()
                ));
            }

            Ok(user)
        } else {
            // User does not exist — create it
            let user_data = UserCreateBuilder::default()
                .name(self.bootstrap_username.clone())
                .domain_id(config.identity.default_domain_id.clone())
                .password(password.to_string())
                .enabled(true)
                .build()?;
            let res = client
                .post(format!("{base_url}/v3/users"))
                .json(&UserCreateRequest { user: user_data })
                .send()
                .await
                .wrap_err("creating new user failed")?;
            if res.status() == StatusCode::CONFLICT {
                // User was created concurrently; fetch it
                let url = format!("{base_url}/v3/users");
                let users = client
                    .get(Url::parse_with_params(
                        &url,
                        &[
                            ("domain_id", config.identity.default_domain_id.clone()),
                            ("name", self.bootstrap_username.clone()),
                        ],
                    )?)
                    .send()
                    .await?
                    .json::<UserList>()
                    .await?
                    .users;
                users
                    .first()
                    .cloned()
                    .ok_or_else(|| eyre!("bootstrap user not found after concurrent creation"))
            } else {
                Ok(res.json::<UserResponse>().await?.user)
            }
        }
    }

    /// Ensure the role exist.
    ///
    /// Create the role when it is not existing.
    ///
    /// # Parameters
    /// * `role_name` - The name of the role.
    async fn upsert_role<S: AsRef<str>>(
        &self,
        client: &Client,
        _config: &Config,
        role_name: S,
        base_url: &str,
    ) -> Result<Role> {
        // Find the existing role
        let url = format!("{base_url}/v3/roles");
        let existing_roles = client
            .get(Url::parse_with_params(
                &url,
                &[("name", role_name.as_ref())],
            )?)
            .send()
            .await?
            .json::<RoleList>()
            .await?
            .roles;
        if let Some(role) = existing_roles.first() {
            Ok(role.to_owned())
        } else {
            let res = client
                .post(format!("{base_url}/v3/roles"))
                .json(&RoleCreateRequest {
                    role: RoleCreateBuilder::default()
                        .name(role_name.as_ref())
                        .build()?,
                })
                .send()
                .await?;
            if res.status() == StatusCode::CONFLICT {
                // Another bootstrap created the role concurrently; fetch it
                let roles = client
                    .get(Url::parse_with_params(
                        &format!("{base_url}/v3/roles"),
                        &[("name", role_name.as_ref())],
                    )?)
                    .send()
                    .await?
                    .json::<RoleList>()
                    .await?
                    .roles;
                roles.first().cloned().ok_or_else(|| {
                    eyre!(
                        "role '{}' not found after concurrent creation",
                        role_name.as_ref()
                    )
                })
            } else {
                Ok(res.json::<RoleResponse>().await?.role)
            }
        }
    }

    /// Ensure the role imply rule exist.
    ///
    /// # Parameters
    /// * `prior_role` - The prior role reference.
    /// * `implied_role` - The implied role reference.
    async fn upsert_implied_role(
        &self,
        client: &Client,
        prior_role: &Role,
        implied_role: &Role,
        base_url: &str,
    ) -> Result<()> {
        let url = format!(
            "{base_url}/v3/roles/{}/implies/{}",
            prior_role.id.clone(),
            implied_role.id.clone()
        );
        if client.head(url.clone()).send().await?.status() == StatusCode::NOT_FOUND {
            let _res = client.put(url).send().await?;
        }
        Ok(())
    }

    /// Ensure the user has a role on the project.
    ///
    /// # Parameters
    /// * `client` - The http client.
    /// * `user` - The user reference.
    /// * `project` - The project reference.
    /// * `role` - The role reference.
    async fn upsert_user_role_project(
        &self,
        client: &Client,
        user: &User,
        project: &Project,
        role: &Role,
        base_url: &str,
    ) -> Result<()> {
        let url = format!(
            "{base_url}/v3/projects/{}/users/{}/roles/{}",
            project.id.clone(),
            user.id.clone(),
            role.id.clone()
        );
        let res = client.put(url.clone()).send().await?;
        if res.status() != StatusCode::NO_CONTENT && res.status() != StatusCode::CONFLICT {
            return Err(eyre!(
                "error setting user role on the project: {:?}",
                res.text().await?
            ));
        }
        Ok(())
    }

    /// Ensure the user has a role on the system.
    ///
    /// # Parameters
    /// * `client` - The http client.
    /// * `user` - The user reference.
    /// * `role` - The role reference.
    async fn upsert_user_role_system(
        &self,
        client: &Client,
        user: &User,
        role: &Role,
        base_url: &str,
    ) -> Result<()> {
        let url = format!(
            "{base_url}/v3/system/users/{}/roles/{}",
            user.id.clone(),
            role.id.clone()
        );
        let res = client.put(url.clone()).send().await?;
        if res.status() != StatusCode::NO_CONTENT && res.status() != StatusCode::CONFLICT {
            return Err(eyre!(
                "error setting user role on the system: {:?}",
                res.text().await?
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use httpmock::{Method, MockServer};
    use openstack_keystone_config::IdentityProvider;
    use reqwest::Client;

    use super::*;

    /// Build a minimal config for bootstrap tests.
    fn test_config() -> Config {
        Config {
            identity: IdentityProvider {
                default_domain_id: "default".to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Build a BootstrapCommand with the default values for a fresh bootstrap.
    fn test_command() -> BootstrapCommand {
        BootstrapCommand {
            bootstrap_project_name: "admin".to_string(),
            bootstrap_password: "secret".to_string(),
            bootstrap_username: "admin".to_string(),
            verbose: 0,
        }
    }

    /// Register the "scaffolding" mocks needed for a full bootstrap flow
    /// (domain, project, all four roles, implications, assignments).
    fn mock_full_bootstrap(server: &MockServer) {
        // Domain
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/domains");
            then.status(201);
        });

        // Project: list empty (so bootstrap creates it)
        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/projects")
                .query_param("name", "admin")
                .query_param("domain_id", "default");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "projects": [] }));
        });

        // Project: create
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/projects");
            then.status(201)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "project": {
                        "id": "proj-1",
                        "name": "admin",
                        "description": "Bootstrap project for initializing the cloud.",
                        "enabled": true,
                        "domain_id": "default",
                        "is_domain": false
                    }
                }));
        });

        // Roles: list empty + create for each
        for role in ["admin", "manager", "member", "reader"] {
            let name = role.to_string();
            server.mock(|when, then| {
                when.method(Method::GET)
                    .path("/v3/roles")
                    .query_param("name", &name);
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body_obj(&serde_json::json!({ "roles": [] }));
            });

            let name2 = role.to_string();
            let id = format!("role-{name}");
            server.mock(|when, then| {
                when.method(Method::POST).path("/v3/roles");
                then.status(201)
                    .header("content-type", "application/json")
                    .json_body_obj(&serde_json::json!({
                        "role": { "id": id, "name": name2 }
                    }));
            });
        }

        // Role implications: HEAD 204 (already exists — skip PUT)
        server.mock(|when, then| {
            when.method(Method::HEAD)
                .path_matches(r"^/v3/roles/.+/implies/.+$");
            then.status(204);
        });

        // Assignments
        server.mock(|when, then| {
            when.method(Method::PUT)
                .path_matches(r"^/v3/projects/.+/users/.+/roles/.+$");
            then.status(204);
        });
        server.mock(|when, then| {
            when.method(Method::PUT)
                .path_matches(r"^/v3/system/users/.+/roles/.+$");
            then.status(204);
        });
    }

    // ─── Helpers to build test structs ─────────────────────────────────────

    fn make_user(id: &str, name: &str, enabled: bool) -> User {
        User {
            id: id.to_string(),
            name: name.to_string(),
            enabled,
            domain_id: "default".to_string(),
            default_project_id: None,
            extra: HashMap::new(),
            federated: None,
            options: None,
            password_expires_at: None,
        }
    }

    fn make_role(id: &str, name: &str) -> Role {
        Role {
            id: id.to_string(),
            name: name.to_string(),
            domain_id: None,
            description: None,
            extra: HashMap::new(),
        }
    }

    fn make_project(id: &str) -> Project {
        Project {
            id: id.to_string(),
            name: "admin".to_string(),
            enabled: true,
            domain_id: "default".to_string(),
            parent_id: None,
            description: None,
            is_domain: false,
            extra: HashMap::new(),
        }
    }

    // ─── Tests ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_bootstrap_success() {
        let server = MockServer::start();
        let base = server.base_url();

        // User list empty + user creation
        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/users")
                .query_param("domain_id", "default")
                .query_param("name", "admin");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "users": [] }));
        });
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/users");
            then.status(201)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "user": {
                        "id": "user-1",
                        "name": "admin",
                        "enabled": true,
                        "domain_id": "default"
                    }
                }));
        });

        mock_full_bootstrap(&server);

        let client = Client::new();
        let config = test_config();
        let result = test_command()
            .bootstrap_with_client(&client, &config, &base, "secret")
            .await;
        assert!(result.is_ok(), "bootstrap should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn test_bootstrap_domain_conflict_is_idempotent() {
        let server = MockServer::start();
        let base = server.base_url();

        // Domain already exists → 409, which should be treated as success
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/domains");
            then.status(409);
        });
        // Project creation mocked to succeed — error will come from user step
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/projects");
            then.status(201)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "project": {
                        "id": "proj-1",
                        "name": "admin",
                        "description": "Bootstrap project for initializing the cloud.",
                        "enabled": true,
                        "domain_id": "default",
                        "is_domain": false
                    }
                }));
        });

        let client = Client::new();
        let config = test_config();
        let result = test_command()
            .bootstrap_with_client(&client, &config, &base, "secret")
            .await;

        // Should err on user step (not mocked), not on domain
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("creating default domain failed"),
            "domain 409 should not cause an error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_bootstrap_user_existing_enabled() {
        let server = MockServer::start();
        let base = server.base_url();

        // User list returns existing, enabled user
        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/users")
                .query_param("domain_id", "default")
                .query_param("name", "admin");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "users": [{
                    "id": "user-1",
                    "name": "admin",
                    "enabled": true,
                    "domain_id": "default"
                }] }));
        });
        // Password verification succeeds
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/auth/tokens");
            then.status(201);
        });

        mock_full_bootstrap(&server);

        let client = Client::new();
        let config = test_config();
        let result = test_command()
            .bootstrap_with_client(&client, &config, &base, "secret")
            .await;
        assert!(
            result.is_ok(),
            "bootstrap with existing enabled user should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_bootstrap_user_existing_disabled_is_updated() {
        let server = MockServer::start();
        let base = server.base_url();

        // User list returns existing but disabled user
        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/users")
                .query_param("domain_id", "default")
                .query_param("name", "admin");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "users": [{
                    "id": "user-1",
                    "name": "admin",
                    "enabled": false,
                    "domain_id": "default"
                }] }));
        });
        // PUT /users/user-1 → returns updated user
        server.mock(|when, then| {
            when.method(Method::PUT).path("/v3/users/user-1");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "user": {
                    "id": "user-1",
                    "name": "admin",
                    "enabled": true,
                    "domain_id": "default"
                } }));
        });
        // Password verification succeeds after update
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/auth/tokens");
            then.status(201);
        });

        mock_full_bootstrap(&server);

        let client = Client::new();
        let config = test_config();
        let result = test_command()
            .bootstrap_with_client(&client, &config, &base, "secret")
            .await;
        assert!(
            result.is_ok(),
            "bootstrap with disabled user should re-enable and succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_bootstrap_password_mismatch_fails() {
        let server = MockServer::start();
        let base = server.base_url();

        // Domain
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/domains");
            then.status(201);
        });
        // Project: list empty
        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/projects")
                .query_param("name", "admin")
                .query_param("domain_id", "default");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "projects": [] }));
        });
        // Project
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/projects");
            then.status(201)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "project": {
                        "id": "proj-1",
                        "name": "admin",
                        "description": "Bootstrap project for initializing the cloud.",
                        "enabled": true,
                        "domain_id": "default",
                        "is_domain": false
                    }
                }));
        });
        // Existing user
        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/users")
                .query_param("domain_id", "default")
                .query_param("name", "admin");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "users": [{
                    "id": "user-1",
                    "name": "admin",
                    "enabled": true,
                    "domain_id": "default"
                }] }));
        });
        // Password verification fails → 401
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/auth/tokens");
            then.status(401).body("Unauthorized");
        });

        let client = Client::new();
        let config = test_config();
        let result = test_command()
            .bootstrap_with_client(&client, &config, &base, "secret")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("password authentication failed"),
            "should fail with password error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_bootstrap_no_admin_interface() {
        let mut config = test_config();
        config.interface_admin = None;

        let cmd = BootstrapCommand {
            bootstrap_project_name: "admin".to_string(),
            bootstrap_password: "secret".to_string(),
            bootstrap_username: "admin".to_string(),
            verbose: 0,
        };

        let result = cmd.take_action(&config).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("admin interface not configured"),
            "should fail when admin interface is missing, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_upsert_role_existing_is_returned() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/roles")
                .query_param("name", "admin");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "roles": [{ "id": "existing-id", "name": "admin" }]
                }));
        });

        let client = Client::new();
        let config = test_config();
        let cmd = test_command();

        let role = cmd.upsert_role(&client, &config, "admin", &base).await;
        assert!(role.is_ok());
        assert_eq!(role.unwrap().id, "existing-id");
    }

    #[tokio::test]
    async fn test_upsert_implied_role_already_exists_is_noop() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::HEAD).path("/v3/roles/a/implies/b");
            then.status(200);
        });

        let prior = make_role("a", "admin");
        let implied = make_role("b", "member");

        let client = Client::new();
        let cmd = test_command();
        let result = cmd
            .upsert_implied_role(&client, &prior, &implied, &base)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_upsert_user_role_project_conflict_is_ok() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::PUT)
                .path_matches(r"^/v3/projects/.+/users/.+/roles/.+$");
            then.status(409);
        });

        let user = make_user("u", "admin", true);
        let project = make_project("p");
        let role = make_role("admin-role", "admin");

        let client = Client::new();
        let cmd = test_command();
        let result = cmd
            .upsert_user_role_project(&client, &user, &project, &role, &base)
            .await;
        assert!(
            result.is_ok(),
            "409 should be treated as success: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_upsert_user_role_system_conflict_is_ok() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::PUT)
                .path_matches(r"^/v3/system/users/.+/roles/.+$");
            then.status(409);
        });

        let user = make_user("u", "admin", true);
        let role = make_role("admin-role", "admin");

        let client = Client::new();
        let cmd = test_command();
        let result = cmd
            .upsert_user_role_system(&client, &user, &role, &base)
            .await;
        assert!(
            result.is_ok(),
            "409 should be treated as success: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_upsert_role_creation() {
        let server = MockServer::start();
        let base = server.base_url();

        // Role list empty
        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/roles")
                .query_param("name", "test-role");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "roles": [] }));
        });
        // Role creation succeeds
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/roles");
            then.status(201)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "role": { "id": "new-role-id", "name": "test-role" }
                }));
        });

        let client = Client::new();
        let config = test_config();
        let cmd = test_command();

        let role = cmd.upsert_role(&client, &config, "test-role", &base).await;
        assert!(role.is_ok());
        assert_eq!(role.unwrap().id, "new-role-id");
    }

    // ─── take_action ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_empty_password_fails() {
        let mut config = test_config();
        // Provide a minimal admin interface so we get past the interface check
        config.interface_admin = Some(openstack_keystone_config::AdminInterface {
            listener: openstack_keystone_config::UnixSocketListener {
                socket_path: "/tmp/keystone.sock".into(),
                trust_domains: vec!["example.org".to_string()],
                peer_uid: None,
                peer_gid: None,
            },
            admin_svid: None,
        });

        let cmd = BootstrapCommand {
            bootstrap_project_name: "admin".to_string(),
            bootstrap_password: "".to_string(),
            bootstrap_username: "admin".to_string(),
            verbose: 0,
        };

        let result = cmd.take_action(&config).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("must not be empty"),
            "should reject empty password, got: {err}"
        );
    }

    // ─── bootstrap_domain ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_bootstrap_domain_no_content() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/domains");
            then.status(204);
        });

        // Project: list empty + create
        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/projects")
                .query_param("name", "admin")
                .query_param("domain_id", "default");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "projects": [] }));
        });
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/projects");
            then.status(201)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "project": {
                        "id": "proj-1",
                        "name": "admin",
                        "description": "Bootstrap project for initializing the cloud.",
                        "enabled": true,
                        "domain_id": "default",
                        "is_domain": false
                    }
                }));
        });

        let client = Client::new();
        let config = test_config();
        let result = test_command()
            .bootstrap_with_client(&client, &config, &base, "secret")
            .await;

        // Should err on user step (not mocked), not on domain 204
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("creating default domain failed"),
            "domain 204 should not cause an error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_bootstrap_domain_error() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/domains");
            then.status(500).body("internal error");
        });

        let client = Client::new();
        let config = test_config();
        let result = test_command()
            .bootstrap_with_client(&client, &config, &base, "secret")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("creating default domain failed") || err.contains("500"),
            "should fail on domain error, got: {err}"
        );
    }

    // ─── bootstrap_project ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_bootstrap_project_existing_is_fetched() {
        let server = MockServer::start();
        let base = server.base_url();

        // Domain
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/domains");
            then.status(201);
        });

        // Project list returns existing project
        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/projects")
                .query_param("name", "admin")
                .query_param("domain_id", "default");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "projects": [{
                        "id": "existing-proj",
                        "name": "admin",
                        "description": null,
                        "enabled": true,
                        "domain_id": "default",
                        "is_domain": false
                    }]
                }));
        });

        // Full project fetch
        server.mock(|when, then| {
            when.method(Method::GET).path("/v3/projects/existing-proj");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "project": {
                        "id": "existing-proj",
                        "name": "admin",
                        "description": "Bootstrap project for initializing the cloud.",
                        "enabled": true,
                        "domain_id": "default",
                        "is_domain": false
                    }
                }));
        });

        // User: list empty + create
        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/users")
                .query_param("domain_id", "default")
                .query_param("name", "admin");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "users": [] }));
        });
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/users");
            then.status(201)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "user": {
                        "id": "user-1",
                        "name": "admin",
                        "enabled": true,
                        "domain_id": "default"
                    }
                }));
        });

        mock_full_bootstrap(&server);

        let client = Client::new();
        let config = test_config();
        let result = test_command()
            .bootstrap_with_client(&client, &config, &base, "secret")
            .await;
        assert!(
            result.is_ok(),
            "bootstrap with existing project should succeed: {:?}",
            result
        );
    }

    // ─── upsert_implied_role ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_upsert_implied_role_not_found_creates() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::HEAD).path("/v3/roles/a/implies/b");
            then.status(404);
        });
        server.mock(|when, then| {
            when.method(Method::PUT).path("/v3/roles/a/implies/b");
            then.status(204);
        });

        let prior = make_role("a", "admin");
        let implied = make_role("b", "member");

        let client = Client::new();
        let cmd = test_command();
        let result = cmd
            .upsert_implied_role(&client, &prior, &implied, &base)
            .await;
        assert!(
            result.is_ok(),
            "should create implication on 404: {:?}",
            result
        );
    }

    // ─── upsert_user_role_project ────────────────────────────────────────

    #[tokio::test]
    async fn test_upsert_user_role_project_no_content() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::PUT)
                .path_matches(r"^/v3/projects/.+/users/.+/roles/.+$");
            then.status(204);
        });

        let user = make_user("u", "admin", true);
        let project = make_project("p");
        let role = make_role("admin-role", "admin");

        let client = Client::new();
        let cmd = test_command();
        let result = cmd
            .upsert_user_role_project(&client, &user, &project, &role, &base)
            .await;
        assert!(
            result.is_ok(),
            "204 should be treated as success: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_upsert_user_role_project_error() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::PUT)
                .path_matches(r"^/v3/projects/.+/users/.+/roles/.+$");
            then.status(500).body("internal error");
        });

        let user = make_user("u", "admin", true);
        let project = make_project("p");
        let role = make_role("admin-role", "admin");

        let client = Client::new();
        let cmd = test_command();
        let result = cmd
            .upsert_user_role_project(&client, &user, &project, &role, &base)
            .await;
        assert!(
            result.is_err(),
            "500 should be treated as error: {:?}",
            result
        );
    }

    // ─── upsert_user_role_system ─────────────────────────────────────────

    #[tokio::test]
    async fn test_upsert_user_role_system_no_content() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::PUT)
                .path_matches(r"^/v3/system/users/.+/roles/.+$");
            then.status(204);
        });

        let user = make_user("u", "admin", true);
        let role = make_role("admin-role", "admin");

        let client = Client::new();
        let cmd = test_command();
        let result = cmd
            .upsert_user_role_system(&client, &user, &role, &base)
            .await;
        assert!(
            result.is_ok(),
            "204 should be treated as success: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_upsert_user_role_system_error() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::PUT)
                .path_matches(r"^/v3/system/users/.+/roles/.+$");
            then.status(500).body("internal error");
        });

        let user = make_user("u", "admin", true);
        let role = make_role("admin-role", "admin");

        let client = Client::new();
        let cmd = test_command();
        let result = cmd
            .upsert_user_role_system(&client, &user, &role, &base)
            .await;
        assert!(
            result.is_err(),
            "500 should be treated as error: {:?}",
            result
        );
    }

    // ─── clap env var integration ────────────────────────────────────────

    #[tokio::test]
    async fn test_bootstrap_password_from_env() {
        temp_env::with_var("OS_BOOTSTRAP_PASSWORD", Some("env-secret"), || {
            // Parse with only the command name — no --bootstrap-password flag —
            // so clap must pick up the value from OS_BOOTSTRAP_PASSWORD
            let cmd = BootstrapCommand::parse_from(["keystone-manage"]);
            assert_eq!(cmd.bootstrap_password, "env-secret");
        });
    }

    #[tokio::test]
    async fn test_bootstrap_username_from_env() {
        temp_env::with_var("OS_BOOTSTRAP_USERNAME", Some("env-user"), || {
            temp_env::with_var("OS_BOOTSTRAP_PASSWORD", Some("secret"), || {
                let cmd = BootstrapCommand::parse_from(["keystone-manage"]);
                assert_eq!(cmd.bootstrap_username, "env-user");
            })
        });
    }

    #[tokio::test]
    async fn test_bootstrap_project_name_from_env() {
        temp_env::with_var("OS_BOOTSTRAP_PROJECT_NAME", Some("env-project"), || {
            temp_env::with_var("OS_BOOTSTRAP_PASSWORD", Some("secret"), || {
                let cmd = BootstrapCommand::parse_from(["keystone-manage"]);
                assert_eq!(cmd.bootstrap_project_name, "env-project");
            })
        });
    }
}
