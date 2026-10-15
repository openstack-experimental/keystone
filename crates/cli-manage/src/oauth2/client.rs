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
//! # OAuth2 client registration commands (ADR 0026 §5).
//!
//! Thin wrappers over the `/v4/oauth2/{domain_id}/clients` API sent over the
//! admin UDS, so the Rego policy still applies.

use std::collections::HashMap;

use async_trait::async_trait;
use clap::{Args, Parser, Subcommand, ValueEnum};
use color_eyre::{Report, eyre::WrapErr, eyre::eyre};
use serde::Serialize;
use serde_json::Value;

use openstack_keystone_api_types::v4::oauth2_client::{
    GrantType, OAuth2Client, OAuth2ClientCreate, OAuth2ClientCreateRequest,
    OAuth2ClientCreateResponse, OAuth2ClientList, OAuth2ClientResponse,
    OAuth2ClientRotateSecretResponse, OAuth2ClientUpdate, OAuth2ClientUpdateRequest,
};
use openstack_keystone_config::LoadedConfig;

use super::{domain_url, get_admin_client};
use crate::PerformAction;

/// Output format of the client commands.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(super) enum OutputFormat {
    /// Human readable lines.
    #[default]
    Text,
    /// The API response as JSON.
    Json,
}

/// Options shared by every client command.
#[derive(Args)]
pub(super) struct Common {
    /// Domain owning the client.
    #[arg(long)]
    domain: String,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// Manage OAuth2 clients (relying parties and machine identities).
#[derive(Parser)]
pub(super) struct ClientCommand {
    #[command(subcommand)]
    command: ClientCommands,
}

#[derive(Subcommand)]
enum ClientCommands {
    /// Register a client. Prints the one-time secret of confidential clients.
    Create(CreateCommand),
    /// List the clients of a domain.
    List(ListCommand),
    /// Show one client.
    Show(ShowCommand),
    /// Update mutable client settings.
    Update(UpdateCommand),
    /// Delete a client and revoke its refresh-token families.
    Delete(DeleteCommand),
    /// Replace the secret of a confidential client.
    RotateSecret(RotateSecretCommand),
}

#[async_trait]
impl PerformAction for ClientCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        match self.command {
            ClientCommands::Create(c) => c.take_action(config).await,
            ClientCommands::List(c) => c.take_action(config).await,
            ClientCommands::Show(c) => c.take_action(config).await,
            ClientCommands::Update(c) => c.take_action(config).await,
            ClientCommands::Delete(c) => c.take_action(config).await,
            ClientCommands::RotateSecret(c) => c.take_action(config).await,
        }
    }
}

fn parse_grant_type(s: &str) -> Result<GrantType, String> {
    serde_json::from_value(Value::String(s.to_string()))
        .map_err(|_| format!("unknown grant type `{s}`"))
}

fn parse_claim(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected key=value, got `{s}`"))
}

/// Build the clients API URL, percent-encoding every path segment.
fn client_url(domain: &str, segments: &[&str]) -> String {
    let mut tail = vec!["clients"];
    tail.extend_from_slice(segments);
    domain_url(domain, &tail)
}

/// Send a request to the clients API and return the parsed JSON body
/// (`Null` for an empty body).
async fn call(
    config: &LoadedConfig,
    method: reqwest::Method,
    domain: &str,
    segments: &[&str],
    query: &[(&str, String)],
    body: Option<&impl Serialize>,
) -> Result<Value, Report> {
    let client = get_admin_client(config).await?;
    let mut req = client
        .request(method, client_url(domain, segments))
        .query(query);
    if let Some(body) = body {
        req = req.json(body);
    }
    let res = req.send().await.wrap_err("oauth2 client request failed")?;
    let status = res.status();
    let text = res
        .text()
        .await
        .wrap_err("reading oauth2 client response body failed")?;
    if !status.is_success() {
        return Err(eyre!("oauth2 client request failed: {status} ({text})"));
    }
    if text.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&text).wrap_err("invalid response body")
}

fn print_json(value: &Value) -> Result<(), Report> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_client(c: &OAuth2Client) {
    let grant_types: Vec<String> = c
        .grant_types
        .iter()
        .map(|g| {
            serde_json::to_value(g)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| format!("{g:?}"))
        })
        .collect();
    println!("provider_id:    {}", c.provider_id);
    println!("client_id:      {}", c.client_id);
    println!("name:           {}", c.name);
    println!("enabled:        {}", c.enabled);
    println!("confidential:   {}", c.confidential);
    println!("require_pkce:   {}", c.require_pkce);
    println!("grant_types:    {}", grant_types.join(", "));
    println!("redirect_uris:  {}", c.redirect_uris.join(", "));
}

/// Register a client.
#[derive(Parser)]
pub(super) struct CreateCommand {
    #[command(flatten)]
    common: Common,
    /// Stable identifier of the registration.
    #[arg(long)]
    provider_id: String,
    /// Display name.
    #[arg(long)]
    name: String,
    /// Register a public client (no secret). Confidential is the default.
    #[arg(long)]
    public: bool,
    /// Redirect URI (repeatable).
    #[arg(long = "redirect-uri")]
    redirect_uris: Vec<String>,
    /// Grant type, for example `authorization_code` (repeatable).
    #[arg(long = "grant-type", value_parser = parse_grant_type)]
    grant_types: Vec<GrantType>,
    /// Allowed scope (repeatable).
    #[arg(long = "scope")]
    scopes: Vec<String>,
    /// Skip the consent page for this client.
    #[arg(long)]
    pre_authorized: bool,
    /// Claims template entry `key=value` (repeatable).
    #[arg(long = "claims-template", value_parser = parse_claim)]
    claims_template: Vec<(String, String)>,
    /// Token endpoint authentication method. Defaults to `none` for public
    /// clients and `client_secret_basic` otherwise.
    #[arg(long)]
    token_endpoint_auth_method: Option<String>,
    /// Do not require PKCE. PKCE is required by default; the server rejects
    /// this for public clients.
    #[arg(long)]
    no_pkce: bool,
    /// Description shown on the consent page.
    #[arg(long)]
    description: Option<String>,
}

#[async_trait]
impl PerformAction for CreateCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let confidential = !self.public;
        let method = self.token_endpoint_auth_method.unwrap_or_else(|| {
            if confidential {
                "client_secret_basic".to_string()
            } else {
                "none".to_string()
            }
        });
        let req = OAuth2ClientCreateRequest {
            oauth2_client: OAuth2ClientCreate {
                allowed_scopes: self.scopes,
                claims_template: self.claims_template.into_iter().collect::<HashMap<_, _>>(),
                confidential,
                grant_types: self.grant_types,
                pre_authorized: self.pre_authorized,
                provider_id: self.provider_id,
                redirect_uris: self.redirect_uris,
                require_pkce: !self.no_pkce,
                token_endpoint_auth_method: method,
                name: self.name,
                description: self.description,
                logo_uri: None,
                policy_uri: None,
                tos_uri: None,
                contacts: Vec::new(),
                post_logout_redirect_uris: Vec::new(),
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
            },
        };
        let body = call(
            config,
            reqwest::Method::POST,
            &self.common.domain,
            &[],
            &[],
            Some(&req),
        )
        .await?;
        match self.common.format {
            OutputFormat::Json => print_json(&body),
            OutputFormat::Text => {
                let res: OAuth2ClientCreateResponse = serde_json::from_value(body)?;
                print_client(&res.oauth2_client);
                if let Some(secret) = res.client_secret {
                    println!("client_secret: {secret}");
                    println!("(shown once, store it now)");
                }
                Ok(())
            }
        }
    }
}

/// List the clients of a domain.
#[derive(Parser)]
pub(super) struct ListCommand {
    #[command(flatten)]
    common: Common,
    /// Only enabled (`true`) or disabled (`false`) clients.
    #[arg(long)]
    enabled: Option<bool>,
    /// Only clients whose name contains this text.
    #[arg(long)]
    name: Option<String>,
}

#[async_trait]
impl PerformAction for ListCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let mut query = Vec::new();
        if let Some(enabled) = self.enabled {
            query.push(("enabled", enabled.to_string()));
        }
        if let Some(name) = self.name {
            query.push(("name", name));
        }
        let body = call(
            config,
            reqwest::Method::GET,
            &self.common.domain,
            &[],
            &query,
            None::<&()>,
        )
        .await?;
        match self.common.format {
            OutputFormat::Json => print_json(&body),
            OutputFormat::Text => {
                let list: OAuth2ClientList = serde_json::from_value(body)?;
                for c in list.oauth2_clients {
                    println!(
                        "{}\t{}\t{}\tenabled={}",
                        c.provider_id, c.client_id, c.name, c.enabled
                    );
                }
                Ok(())
            }
        }
    }
}

/// Show one client.
#[derive(Parser)]
pub(super) struct ShowCommand {
    #[command(flatten)]
    common: Common,
    /// Registration identifier.
    #[arg(long)]
    provider_id: String,
}

#[async_trait]
impl PerformAction for ShowCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let body = call(
            config,
            reqwest::Method::GET,
            &self.common.domain,
            &[&self.provider_id],
            &[],
            None::<&()>,
        )
        .await?;
        match self.common.format {
            OutputFormat::Json => print_json(&body),
            OutputFormat::Text => {
                let res: OAuth2ClientResponse = serde_json::from_value(body)?;
                print_client(&res.oauth2_client);
                Ok(())
            }
        }
    }
}

/// Update mutable client settings.
#[derive(Parser)]
pub(super) struct UpdateCommand {
    #[command(flatten)]
    common: Common,
    /// Registration identifier.
    #[arg(long)]
    provider_id: String,
    /// New display name.
    #[arg(long)]
    name: Option<String>,
    /// Enable or disable the client.
    #[arg(long)]
    enabled: Option<bool>,
    /// Replace the redirect URIs (repeatable). Lists cannot be emptied from
    /// the CLI.
    #[arg(long = "redirect-uri")]
    redirect_uris: Option<Vec<String>>,
    /// Replace the grant types (repeatable).
    #[arg(long = "grant-type", value_parser = parse_grant_type)]
    grant_types: Option<Vec<GrantType>>,
    /// Replace the allowed scopes (repeatable).
    #[arg(long = "scope")]
    scopes: Option<Vec<String>>,
    /// Set whether consent is skipped.
    #[arg(long)]
    pre_authorized: Option<bool>,
    /// Set whether PKCE is required.
    #[arg(long)]
    require_pkce: Option<bool>,
    /// New description; an empty string clears it.
    #[arg(long)]
    description: Option<String>,
    /// Replace the claims template with `key=value` entries (repeatable).
    #[arg(long = "claims-template", value_parser = parse_claim)]
    claims_template: Option<Vec<(String, String)>>,
}

#[async_trait]
impl PerformAction for UpdateCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let req = OAuth2ClientUpdateRequest {
            oauth2_client: OAuth2ClientUpdate {
                name: self.name,
                enabled: self.enabled,
                redirect_uris: self.redirect_uris,
                grant_types: self.grant_types,
                allowed_scopes: self.scopes,
                pre_authorized: self.pre_authorized,
                require_pkce: self.require_pkce,
                description: self.description,
                claims_template: self.claims_template.map(|c| c.into_iter().collect()),
                ..Default::default()
            },
        };
        let body = call(
            config,
            reqwest::Method::PUT,
            &self.common.domain,
            &[&self.provider_id],
            &[],
            Some(&req),
        )
        .await?;
        match self.common.format {
            OutputFormat::Json => print_json(&body),
            OutputFormat::Text => {
                let res: OAuth2ClientResponse = serde_json::from_value(body)?;
                print_client(&res.oauth2_client);
                Ok(())
            }
        }
    }
}

/// Delete a client.
#[derive(Parser)]
pub(super) struct DeleteCommand {
    #[command(flatten)]
    common: Common,
    /// Registration identifier.
    #[arg(long)]
    provider_id: String,
}

#[async_trait]
impl PerformAction for DeleteCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        call(
            config,
            reqwest::Method::DELETE,
            &self.common.domain,
            &[&self.provider_id],
            &[],
            None::<&()>,
        )
        .await?;
        match self.common.format {
            OutputFormat::Json => print_json(&serde_json::json!({"deleted": self.provider_id})),
            OutputFormat::Text => {
                println!("deleted client {}", self.provider_id);
                Ok(())
            }
        }
    }
}

/// Rotate the secret of a confidential client.
#[derive(Parser)]
pub(super) struct RotateSecretCommand {
    #[command(flatten)]
    common: Common,
    /// Registration identifier.
    #[arg(long)]
    provider_id: String,
}

#[async_trait]
impl PerformAction for RotateSecretCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let body = call(
            config,
            reqwest::Method::POST,
            &self.common.domain,
            &[&self.provider_id, "rotate-secret"],
            &[],
            None::<&()>,
        )
        .await?;
        match self.common.format {
            OutputFormat::Json => print_json(&body),
            OutputFormat::Text => {
                let res: OAuth2ClientRotateSecretResponse = serde_json::from_value(body)?;
                println!("client_secret: {}", res.client_secret);
                println!("(shown once, store it now)");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Wrapper {
        #[command(subcommand)]
        command: ClientCommands,
    }

    #[test]
    fn test_parses_create() {
        let w = Wrapper::parse_from([
            "client",
            "create",
            "--domain",
            "d1",
            "--provider-id",
            "p1",
            "--name",
            "Grafana",
            "--public",
            "--redirect-uri",
            "https://a/cb",
            "--redirect-uri",
            "https://b/cb",
            "--grant-type",
            "authorization_code",
            "--scope",
            "openid",
            "--claims-template",
            "team=ops",
            "--format",
            "json",
        ]);
        let ClientCommands::Create(c) = w.command else {
            panic!("expected create");
        };
        assert!(c.public);
        assert_eq!(c.redirect_uris.len(), 2);
        assert_eq!(c.grant_types, vec![GrantType::AuthorizationCode]);
        assert_eq!(c.claims_template, vec![("team".into(), "ops".into())]);
        assert!(matches!(c.common.format, OutputFormat::Json));
    }

    #[test]
    fn test_rejects_bad_claim_and_grant() {
        assert!(
            Wrapper::try_parse_from([
                "client",
                "create",
                "--domain",
                "d",
                "--provider-id",
                "p",
                "--name",
                "n",
                "--claims-template",
                "nokv",
            ])
            .is_err()
        );
        assert!(
            Wrapper::try_parse_from([
                "client",
                "create",
                "--domain",
                "d",
                "--provider-id",
                "p",
                "--name",
                "n",
                "--grant-type",
                "bogus",
            ])
            .is_err()
        );
    }

    #[test]
    fn test_parses_other_subcommands() {
        for args in [
            vec!["client", "list", "--domain", "d"],
            vec!["client", "show", "--domain", "d", "--provider-id", "p"],
            vec![
                "client",
                "update",
                "--domain",
                "d",
                "--provider-id",
                "p",
                "--enabled",
                "false",
            ],
            vec!["client", "delete", "--domain", "d", "--provider-id", "p"],
            vec![
                "client",
                "rotate-secret",
                "--domain",
                "d",
                "--provider-id",
                "p",
            ],
        ] {
            assert!(Wrapper::try_parse_from(args).is_ok());
        }
    }

    #[test]
    fn test_client_url_encodes_segments() {
        assert_eq!(
            client_url("d1", &[]),
            "https://localhost/v4/oauth2/d1/clients"
        );
        assert_eq!(
            client_url("d/1?x", &["p#1", "rotate-secret"]),
            "https://localhost/v4/oauth2/d%2F1%3Fx/clients/p%231/rotate-secret"
        );
        assert_eq!(
            client_url("d", &["../x"]),
            "https://localhost/v4/oauth2/d/clients/..%2Fx"
        );
    }

    #[test]
    fn test_parses_update_extras() {
        let w = Wrapper::parse_from([
            "client",
            "update",
            "--domain",
            "d",
            "--provider-id",
            "p",
            "--require-pkce",
            "true",
            "--description",
            "",
            "--claims-template",
            "a=b",
        ]);
        let ClientCommands::Update(c) = w.command else {
            panic!("expected update");
        };
        assert_eq!(c.require_pkce, Some(true));
        assert_eq!(c.description.as_deref(), Some(""));
        assert_eq!(c.claims_template, Some(vec![("a".into(), "b".into())]));
    }

    #[tokio::test]
    async fn test_rejects_missing_admin_interface_config() {
        let cfg = LoadedConfig::new(Default::default());
        let cmd = ShowCommand {
            common: Common {
                domain: "d".into(),
                format: OutputFormat::Text,
            },
            provider_id: "p".into(),
        };
        let err = cmd.take_action(&cfg).await.unwrap_err();
        assert!(err.to_string().contains("admin interface not configured"));
    }
}
