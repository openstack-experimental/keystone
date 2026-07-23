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
//! Shared provisioning for the live-HTTP `/SCIM/v2` suites: a realm, an
//! API Key, and the `ApiClient`-sourced mapping ruleset that grants the
//! resulting ephemeral identity the `scim_provisioner` role (ADR 0024 §8) --
//! everything the Realm Activation Gate and `identity/scim/*` policies
//! require before a single `/SCIM/v2` request can succeed.

use std::sync::Arc;

use eyre::Result;
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use openstack_keystone_api_types::federation::IdentityProvider;
use openstack_keystone_api_types::v3::role::{Role, RoleCreateBuilder, RoleImply, RoleRef};
use openstack_keystone_api_types::v4::api_key::ApiKeyCreateResponse;
use openstack_keystone_api_types::v4::mapping::ruleset::{
    Authorization, DomainResolutionMode, IdentityBinding, IdentitySource, MappingRule,
    MappingRuleSet, MappingRuleSetCreate, MatchCriteria,
};
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::api_key::{create_api_key, sample_api_key_create};
use test_api::federation::identity_provider::*;
use test_api::guard::{AsyncResourceGuard, ResourceGuard};
use test_api::mapping::ruleset::*;
use test_api::role::imply::create_implied_role;
use test_api::role::{create_role, list_roles};
use test_api::scim::ScimTestClient;
use test_api::scim_realm::*;

/// Everything provisioned for one `/SCIM/v2` live test: drop order doesn't
/// matter for the SCIM realm (no delete endpoint, ADR 0024 §2.B), but the
/// other resources are explicitly torn down via `cleanup()`.
pub struct ProvisionedScim {
    pub client: ScimTestClient,
    admin: Arc<AsyncOpenStack>,
    domain_id: String,
    provider_id: String,
    idp: AsyncResourceGuard<IdentityProvider>,
    api_key: AsyncResourceGuard<ApiKeyCreateResponse>,
    ruleset: AsyncResourceGuard<MappingRuleSet>,
    role_imply: AsyncResourceGuard<RoleImply>,
    role: AsyncResourceGuard<Role>,
}

/// Gracefully deletes a resource, logging a warning instead of panicking
/// when a 401 (Unauthorized) is returned. This handles the known issue where
/// `AsyncOpenStack`'s cached token loses role resolution after prolonged use.
async fn delete_or_warn(resource: impl ResourceGuard) -> Result<()> {
    match resource.delete().await {
        Ok(()) => Ok(()),
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("401")
                || err_str.contains("unauthorized")
                || err_str.contains("Unauthorized")
                || err_str.contains("ActorHasNoRolesOnTarget")
            {
                eprintln!(
                    "WARNING: cleanup skipped due to auth loss (401): {}",
                    err_str.lines().next().unwrap_or(&err_str)
                );
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

impl ProvisionedScim {
    /// Permanently remove one already-deprovisioned SCIM resource so tests do
    /// not leave tombstones or membership rows on a long-lived API server.
    pub async fn purge_resource(&self, resource_type: &str, keystone_id: &str) -> Result<()> {
        test_api::scim_realm::purge_resource(
            &self.admin,
            &self.domain_id,
            &self.provider_id,
            resource_type,
            keystone_id,
        )
        .await
    }

    pub async fn cleanup(self) -> Result<()> {
        delete_or_warn(self.ruleset).await?;
        delete_or_warn(self.api_key).await?;
        delete_or_warn(self.role_imply).await?;
        delete_or_warn(self.role).await?;
        delete_or_warn(self.idp).await?;
        Ok(())
    }
}

/// Provision a fresh, uniquely-named realm + API Key + mapping ruleset in
/// the `default` domain, whose `ApiClient` identity is granted the
/// `scim_provisioner` role -- returns a ready-to-use [`ScimTestClient`].
pub async fn provision_scim_realm() -> Result<ProvisionedScim> {
    provision(true).await
}

/// Same provisioning, but the mapping ruleset's rule grants no roles at
/// all: the Realm Activation Gate (§2.B) still admits the request, but
/// `identity/scim/*` handler-level policy must deny it -- see
/// `user::test_create_denied_without_scim_provisioner_role`.
pub async fn provision_scim_realm_without_role() -> Result<ProvisionedScim> {
    provision(false).await
}

async fn provision(grant_role: bool) -> Result<ProvisionedScim> {
    let admin = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let unique = Uuid::new_v4().simple().to_string();
    let domain_id = "default".to_string();
    let provider_id = format!("scim-v2-test-{unique}");

    let idp = create_identity_provider(
        &admin,
        sample_identity_provider_create(&domain_id, &format!("scim-v2-idp-{unique}")),
    )
    .await?;

    create_realm(
        &admin,
        sample_realm_create(&domain_id, &provider_id, &idp.id),
    )
    .await?;

    let manager_role = list_roles(&admin)
        .await?
        .into_iter()
        .find(|r| r.name == "manager")
        .expect("manager role must exist");

    let role = create_role(
        &admin,
        RoleCreateBuilder::default()
            .name("scim_provisioner".to_string())
            .build()?,
    )
    .await?;

    let role_imply = AsyncResourceGuard::new(
        create_implied_role(&admin, &role.id, &manager_role.id).await?,
        admin.clone(),
    );

    let authorizations = if grant_role {
        vec![Authorization::Domain {
            domain_id: domain_id.clone(),
            roles: vec![RoleRef::from(&role)],
        }]
    } else {
        vec![]
    };

    let ruleset = create_ruleset(
        &admin,
        MappingRuleSetCreate {
            mapping_id: Some(format!("scim-v2-mapping-{unique}")),
            domain_id: Some(domain_id.clone()),
            source: IdentitySource::ApiClient {
                provider_id: provider_id.clone(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![MappingRule {
                name: "scim-v2-test-rule".to_string(),
                description: None,
                r#match: MatchCriteria::AllOf(vec![]),
                identity: IdentityBinding {
                    identity_mode: None,
                    user_name: "${claims.api_client.client_id}".to_string(),
                    user_id: None,
                    user_domain_id: None,
                    is_system: false,
                },
                authorizations,
                groups: vec![],
            }],
        },
    )
    .await?;

    let api_key = create_api_key(&admin, sample_api_key_create(&domain_id, &provider_id)).await?;
    let token = SecretString::from(api_key.token.expose_secret().to_string());

    let client = ScimTestClient::new(domain_id.clone(), token)?;

    Ok(ProvisionedScim {
        client,
        admin: admin.clone(),
        domain_id,
        provider_id,
        idp,
        api_key,
        ruleset,
        role: AsyncResourceGuard::new(role, admin.clone()),
        role_imply,
    })
}
