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
//! # Bulk revocation of OAuth2 sessions (ADR 0026 §9).

use async_trait::async_trait;
use clap::{ArgGroup, Parser};
use color_eyre::{Report, eyre::WrapErr, eyre::eyre};

use openstack_keystone_api_types::v4::oauth2_revocation::{
    Oauth2RevocationRequest, Oauth2RevocationResponse,
};
use openstack_keystone_config::LoadedConfig;

use super::client::OutputFormat;
use super::{domain_url, get_admin_client};
use crate::PerformAction;

/// Revoke the refresh token families of a user, a client or a whole domain,
/// for example during an incident.
#[derive(Parser)]
#[command(group(ArgGroup::new("target").required(true).args(["user", "client", "all"])))]
pub(super) struct RevokeCommand {
    /// Domain the revocation applies to.
    #[arg(long)]
    domain: String,
    /// Revoke every session of this user.
    #[arg(long)]
    user: Option<String>,
    /// Revoke every session issued to this `client_id`.
    #[arg(long)]
    client: Option<String>,
    /// Revoke every session in the domain.
    #[arg(long)]
    all: bool,
    /// Reason recorded in the server log.
    #[arg(long)]
    reason: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[async_trait]
impl PerformAction for RevokeCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let client = get_admin_client(config).await?;
        let req = Oauth2RevocationRequest {
            user_id: self.user,
            client_id: self.client,
            all: self.all,
            reason: self.reason,
        };
        let res = client
            .post(domain_url(&self.domain, &["revocations"]))
            .json(&req)
            .send()
            .await
            .wrap_err("revocation request failed")?;
        let status = res.status();
        if !status.is_success() {
            let text = res
                .text()
                .await
                .wrap_err("reading revocation response body failed")?;
            return Err(eyre!("revocation failed: {status} ({text})"));
        }
        let body: Oauth2RevocationResponse = res.json().await?;
        match self.format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&body)?),
            OutputFormat::Text => println!("revoked {} session families", body.revoked_families),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn test_requires_one_target() {
        assert!(RevokeCommand::try_parse_from(["revoke", "--domain", "d"]).is_err());
        assert!(RevokeCommand::try_parse_from(["revoke", "--domain", "d", "--user", "u"]).is_ok());
        assert!(
            RevokeCommand::try_parse_from(["revoke", "--domain", "d", "--client", "c"]).is_ok()
        );
        assert!(RevokeCommand::try_parse_from(["revoke", "--domain", "d", "--all"]).is_ok());
        assert!(
            RevokeCommand::try_parse_from(["revoke", "--domain", "d", "--all", "--user", "u"])
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_rejects_missing_admin_interface_config() {
        let cfg = LoadedConfig::new(Default::default());
        let cmd = RevokeCommand::try_parse_from(["revoke", "--domain", "d", "--all"]).unwrap();
        let err = cmd.take_action(&cfg).await.unwrap_err();
        assert!(err.to_string().contains("admin interface not configured"));
    }
}
