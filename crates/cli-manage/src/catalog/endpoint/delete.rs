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

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{Report, eyre::eyre};
use eyre::Result;
use reqwest::{Client, StatusCode};

use openstack_keystone_config::Config;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client};

/// Delete a catalog endpoint.
#[derive(Parser)]
pub(super) struct DeleteCommand {
    /// The ID of the endpoint to delete.
    id: String,
}

impl DeleteCommand {
    /// Delete the endpoint against a pre-built HTTP client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn delete_with_client(&self, client: &Client, base_url: &str) -> Result<()> {
        let res = client
            .delete(format!("{base_url}/v3/endpoints/{}", self.id))
            .send()
            .await?;

        if res.status() != StatusCode::NO_CONTENT {
            return Err(eyre!(
                "failed to delete endpoint: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        Ok(())
    }
}

#[async_trait]
impl PerformAction for DeleteCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        self.delete_with_client(&client, ADMIN_BASE_URL).await?;
        println!("Deleted endpoint {}", self.id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use httpmock::{Method, MockServer};
    use reqwest::Client;

    use super::*;

    #[tokio::test]
    async fn test_delete_endpoint() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::DELETE).path("/v3/endpoints/ep-1");
            then.status(204);
        });

        let client = Client::new();
        let cmd = DeleteCommand {
            id: "ep-1".to_string(),
        };
        let result = cmd.delete_with_client(&client, &base).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_endpoint_not_found() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::DELETE).path("/v3/endpoints/missing");
            then.status(404).body("not found");
        });

        let client = Client::new();
        let cmd = DeleteCommand {
            id: "missing".to_string(),
        };
        let result = cmd.delete_with_client(&client, &base).await;
        assert!(result.is_err());
    }
}
