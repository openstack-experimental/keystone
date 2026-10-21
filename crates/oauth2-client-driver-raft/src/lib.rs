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
//! # OpenStack Keystone Raft driver for OAuth2 client (relying party)
//! registration (ADR 0026 §5).
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use std::sync::Arc;

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::oauth2_client::Oauth2ClientProviderError;
use openstack_keystone_core::oauth2_client::backend::Oauth2ClientBackend;
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core_types::oauth2_client::*;
use openstack_keystone_distributed_storage::{
    ApiStoreError, Metadata, StorageApi, StoreDataEnvelope, StoreError, StoreResponse,
    store_command::Mutation,
};

/// Bridges two different backend behaviors for the same semantic event: the
/// real Raft-backed [`StorageApi`] converts the first `Violation` on a
/// `transaction` call into an immediate `Err(ApiStoreError::Conflict)`;
/// `MockStorage`, used by this crate's own unit tests, instead returns every
/// violation as data on an `Ok` response's `violations` field. Both call
/// sites need conflict detection to behave identically against either
/// backend (mirrors `scim-driver-raft`'s helper of the same name).
fn require_no_conflict(
    result: Result<StoreResponse, ApiStoreError>,
    conflict: impl FnOnce() -> StoreError,
) -> Result<StoreResponse, StoreError> {
    match result {
        Ok(response) if response.violations.is_empty() => Ok(response),
        Ok(_) => Err(conflict()),
        Err(ApiStoreError::Conflict { .. }) => Err(conflict()),
        Err(e) => Err(e.into()),
    }
}

/// Global `client_id` index value payload: resolves to the owning
/// `(domain_id, provider_id)` coordinate. Stored as a
/// `Mutation::create_if_absent` data key (not `set_index`, which carries no
/// payload) since `client_id` is unique cluster-wide, not domain-scoped --
/// looking it up needs to recover which domain owns it.
#[derive(Clone, Deserialize, Serialize)]
struct ClientIdIndexEntry {
    domain_id: String,
    provider_id: String,
}

/// Raft Database OAuth2 client backend.
///
/// Primary records are indexed by `(domain_id, provider_id)` (`provider_id`
/// unique within `domain_id`). The public `client_id` UUID is resolved
/// cluster-wide (not domain-scoped, ADR 0026 §5) through a secondary index.
#[derive(Default)]
pub struct RaftOauth2ClientBackend {}

impl RaftOauth2ClientBackend {
    /// Primary storage key: `oauth2:client:v1:<domain_id>:<provider_id>`.
    fn get_resource_key_name<D: AsRef<str>, P: AsRef<str>>(
        &self,
        domain_id: D,
        provider_id: P,
    ) -> String {
        format!(
            "oauth2:client:v1:{}:{}",
            domain_id.as_ref(),
            provider_id.as_ref()
        )
    }

    /// Prefix covering all keys for a domain (used for listing).
    fn get_resource_by_domain_prefix<D: AsRef<str>>(&self, domain_id: D) -> String {
        format!("oauth2:client:v1:{}:", domain_id.as_ref())
    }

    /// Per-domain settings key: `oauth2:domain_settings:v1:<domain_id>`.
    fn get_domain_settings_key_name<D: AsRef<str>>(&self, domain_id: D) -> String {
        format!("oauth2:domain_settings:v1:{}", domain_id.as_ref())
    }

    /// Global `client_id` index key:
    /// `oauth2:client:client_id_idx:v1:<client_id>`.
    fn get_client_id_idx_key_name<C: AsRef<str>>(&self, client_id: C) -> String {
        format!("oauth2:client:client_id_idx:v1:{}", client_id.as_ref())
    }

    async fn create_impl(
        &self,
        storage: &dyn StorageApi,
        data: OAuth2ClientResourceCreate,
    ) -> Result<OAuth2ClientResource, StoreError> {
        let now = Utc::now().timestamp();
        let obj = OAuth2ClientResource {
            client_id: data.client_id,
            provider_id: data.provider_id,
            domain_id: data.domain_id,
            client_secret_hash: data.client_secret_hash,
            redirect_uris: data.redirect_uris,
            token_endpoint_auth_method: data.token_endpoint_auth_method,
            grant_types: data.grant_types,
            require_pkce: data.require_pkce,
            allowed_scopes: data.allowed_scopes,
            pre_authorized: data.pre_authorized,
            enabled: true,
            claims_template: data.claims_template,
            created_at: now,
            updated_at: now,
            deleted_at: None,
            name: data.name,
            description: data.description,
            logo_uri: data.logo_uri,
            policy_uri: data.policy_uri,
            tos_uri: data.tos_uri,
            contacts: data.contacts,
            post_logout_redirect_uris: data.post_logout_redirect_uris,
            backchannel_logout_uri: data.backchannel_logout_uri,
            backchannel_logout_session_required: data.backchannel_logout_session_required,
            frontchannel_logout_uri: data.frontchannel_logout_uri,
            frontchannel_logout_session_required: data.frontchannel_logout_session_required,
            spiffe_ids: data.spiffe_ids,
            delegation: data.delegation,
            dpop_bound_access_tokens: data.dpop_bound_access_tokens,
        };
        let primary_key = self.get_resource_key_name(&obj.domain_id, &obj.provider_id);
        let index_key = self.get_client_id_idx_key_name(&obj.client_id);

        // The atomic `create_if_absent` transaction below only reports "some
        // violation happened", not which of the two keys it was. Check both
        // up front to name the actual offender in the conflict message --
        // this is a best-effort read (TOCTOU-racy against a concurrent
        // create) that only affects the error *text*, never correctness:
        // the transaction itself is still the sole source of truth for
        // whether the create succeeds.
        let primary_exists = storage
            .get_by_key(primary_key.as_bytes(), None)
            .await?
            .is_some();
        let index_exists = storage
            .get_by_key(index_key.as_bytes(), None)
            .await?
            .is_some();
        let conflict_description = match (primary_exists, index_exists) {
            (true, _) => format!(
                "provider_id `{}` already registered in domain `{}`",
                obj.provider_id, obj.domain_id
            ),
            (false, true) => format!("client_id `{}` already in use", obj.client_id),
            (false, false) => format!(
                "provider_id `{}` or client_id `{}` already in use",
                obj.provider_id, obj.client_id
            ),
        };

        let mutations = vec![
            Mutation::create_if_absent(
                primary_key.clone(),
                obj.clone(),
                Metadata::new(),
                None::<&str>,
            )?,
            Mutation::create_if_absent(
                index_key,
                ClientIdIndexEntry {
                    domain_id: obj.domain_id.clone(),
                    provider_id: obj.provider_id.clone(),
                },
                Metadata::new(),
                None::<&str>,
            )?,
        ];
        require_no_conflict(storage.transaction(mutations).await, move || {
            StoreError::Conflict {
                subject: primary_key.clone(),
                description: conflict_description,
            }
        })?;
        Ok(obj)
    }

    /// Soft-delete: disables the client and stamps the tombstone. The
    /// `client_id_idx` entry is deliberately left in place (unlike
    /// `api-key-driver-raft`'s hard-delete `purge_impl`, which removes both)
    /// -- `get_by_client_id` must keep resolving a soft-deleted client so
    /// the disabled record stays reachable, which is the entire point of
    /// choosing soft- over hard-delete here (Phase 4's refresh-token
    /// family-tree invalidation walk needs it, and callers can still tell
    /// it's revoked via `enabled`/`deleted_at`). There is currently no
    /// physical-reclamation sweep for either the primary record or this
    /// index entry; add one (mirroring `api_key`'s janitor,
    /// ADR 0021 §6.F) if unbounded growth becomes a concern.
    async fn delete_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        provider_id: &str,
    ) -> Result<OAuth2ClientResource, StoreError> {
        let key = self.get_resource_key_name(domain_id, provider_id);
        let curr: StoreDataEnvelope<OAuth2ClientResource> = storage
            .get_by_key(key.as_bytes(), None)
            .await?
            .ok_or_else(|| StoreError::IO {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            })?
            .try_deserialize()?;
        let new = curr.data.soft_delete(Utc::now().timestamp());
        let new_meta = curr.metadata.new_revision();
        storage
            .set_value(
                key,
                StoreDataEnvelope {
                    data: rmp_serde::to_vec(&new)?,
                    metadata: new_meta,
                },
                None,
                Some(curr.metadata.revision),
            )
            .await?;
        Ok(new)
    }

    async fn get_by_client_id_impl(
        &self,
        storage: &dyn StorageApi,
        client_id: &str,
    ) -> Result<Option<OAuth2ClientResource>, StoreError> {
        let Some(entry) = storage
            .get_by_key(self.get_client_id_idx_key_name(client_id).as_bytes(), None)
            .await?
            .map(|env| env.try_deserialize::<ClientIdIndexEntry>())
            .transpose()?
            .map(|x| x.data)
        else {
            return Ok(None);
        };
        self.get_impl(storage, &entry.domain_id, &entry.provider_id)
            .await
    }

    async fn get_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        provider_id: &str,
    ) -> Result<Option<OAuth2ClientResource>, StoreError> {
        Ok(storage
            .get_by_key(
                self.get_resource_key_name(domain_id, provider_id)
                    .as_bytes(),
                None,
            )
            .await?
            .map(|env| env.try_deserialize::<OAuth2ClientResource>())
            .transpose()?
            .map(|x| x.data))
    }

    async fn list_spiffe_clients_impl(
        &self,
        storage: &dyn StorageApi,
    ) -> Result<Vec<OAuth2ClientResource>, StoreError> {
        let mut res: Vec<OAuth2ClientResource> = Vec::new();
        for (_, envelope) in storage.prefix(b"oauth2:client:v1:", None).await? {
            let candidate = envelope.try_deserialize::<OAuth2ClientResource>()?.data;
            if candidate.deleted_at.is_none() && !candidate.spiffe_ids.is_empty() {
                res.push(candidate);
            }
        }
        Ok(res)
    }

    async fn list_impl(
        &self,
        storage: &dyn StorageApi,
        params: &OAuth2ClientResourceListParameters,
    ) -> Result<Vec<OAuth2ClientResource>, StoreError> {
        let prefix = self.get_resource_by_domain_prefix(&params.domain_id);
        let mut res: Vec<OAuth2ClientResource> = Vec::new();
        for (_, envelope) in storage.prefix(prefix.as_bytes(), None).await? {
            let candidate = envelope.try_deserialize::<OAuth2ClientResource>()?.data;
            if let Some(enabled) = params.enabled
                && candidate.enabled != enabled
            {
                continue;
            }
            if let Some(needle) = &params.name
                && !candidate
                    .display_name()
                    .to_lowercase()
                    .contains(&needle.to_lowercase())
            {
                continue;
            }
            res.push(candidate);
        }

        res.sort_by(|a, b| a.provider_id.cmp(&b.provider_id));
        if let Some(marker) = &params.pagination.marker {
            if params.pagination.page_reverse {
                res.retain(|x| x.provider_id.as_str() < marker.as_str());
            } else {
                res.retain(|x| x.provider_id.as_str() > marker.as_str());
            }
        }
        if let Some(limit) = params.pagination.limit {
            let limit = (limit + 1) as usize;
            if params.pagination.page_reverse {
                if res.len() > limit {
                    res = res.split_off(res.len() - limit);
                }
            } else {
                res.truncate(limit);
            }
        }
        Ok(res)
    }

    async fn list_delegatable_impl(
        &self,
        storage: &dyn StorageApi,
    ) -> Result<Vec<OAuth2ClientResource>, StoreError> {
        // A full scan of the client keyspace (ADR 0036 §3). Client counts
        // are small; an index can replace it if that changes.
        let mut res: Vec<OAuth2ClientResource> = Vec::new();
        for (_, envelope) in storage.prefix(b"oauth2:client:v1:", None).await? {
            let candidate = envelope.try_deserialize::<OAuth2ClientResource>()?.data;
            if candidate.service_grant_policy().is_some() {
                res.push(candidate);
            }
        }
        res.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        Ok(res)
    }

    async fn get_domain_settings_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
    ) -> Result<Option<OAuth2DomainSettings>, StoreError> {
        Ok(storage
            .get_by_key(
                self.get_domain_settings_key_name(domain_id).as_bytes(),
                None,
            )
            .await?
            .map(|env| env.try_deserialize::<OAuth2DomainSettings>())
            .transpose()?
            .map(|x| x.data))
    }

    /// Create the settings record on first use, otherwise update it with a
    /// compare-and-swap on the stored revision.
    ///
    /// An update that changes nothing is not written: a domain without a
    /// record already behaves as if it had the defaults.
    async fn update_domain_settings_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        data: OAuth2DomainSettingsUpdate,
    ) -> Result<OAuth2DomainSettings, StoreError> {
        let key = self.get_domain_settings_key_name(domain_id);
        let now = Utc::now().timestamp();
        let curr = storage
            .get_by_key(key.as_bytes(), None)
            .await?
            .map(|env| env.try_deserialize::<OAuth2DomainSettings>())
            .transpose()?;
        let conflict = || StoreError::Conflict {
            subject: key.clone(),
            description: format!(
                "the OAuth2 settings of domain `{domain_id}` were changed concurrently"
            ),
        };
        let (new, mutation) = match curr {
            Some(curr) => {
                let new = curr.data.clone().with_update(data, now);
                if new == curr.data {
                    return Ok(new);
                }
                let mutation = Mutation::set(
                    key.clone(),
                    &new,
                    curr.metadata.new_revision(),
                    None::<&str>,
                    Some(curr.metadata.revision),
                )?;
                (new, mutation)
            }
            None => {
                let defaults = OAuth2DomainSettings::default_for(domain_id);
                let new = defaults.clone().with_update(data, now);
                if new == defaults {
                    return Ok(new);
                }
                let mutation =
                    Mutation::create_if_absent(key.clone(), &new, Metadata::new(), None::<&str>)?;
                (new, mutation)
            }
        };
        require_no_conflict(storage.transaction(vec![mutation]).await, conflict)?;
        Ok(new)
    }

    /// Remove the settings record, if any, guarded by the stored revision.
    async fn delete_domain_settings_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
    ) -> Result<(), StoreError> {
        let key = self.get_domain_settings_key_name(domain_id);
        let Some(curr) = storage.get_by_key(key.as_bytes(), None).await? else {
            return Ok(());
        };
        require_no_conflict(
            storage
                .transaction(vec![Mutation::remove(
                    key.clone(),
                    None::<&str>,
                    Some(curr.metadata.revision),
                )])
                .await,
            || StoreError::Conflict {
                subject: key,
                description: format!(
                    "the OAuth2 settings of domain `{domain_id}` were changed concurrently"
                ),
            },
        )?;
        Ok(())
    }

    async fn rotate_secret_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        provider_id: &str,
        client_secret_hash: String,
    ) -> Result<OAuth2ClientResource, StoreError> {
        let key = self.get_resource_key_name(domain_id, provider_id);
        let curr: StoreDataEnvelope<OAuth2ClientResource> = storage
            .get_by_key(key.as_bytes(), None)
            .await?
            .ok_or_else(|| StoreError::IO {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            })?
            .try_deserialize()?;
        let mut new = curr.data;
        new.client_secret_hash = Some(client_secret_hash);
        new.updated_at = Utc::now().timestamp();
        let new_meta = curr.metadata.new_revision();
        storage
            .set_value(
                key,
                StoreDataEnvelope {
                    data: rmp_serde::to_vec(&new)?,
                    metadata: new_meta,
                },
                None,
                Some(curr.metadata.revision),
            )
            .await?;
        Ok(new)
    }

    async fn update_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        provider_id: &str,
        data: OAuth2ClientResourceUpdate,
    ) -> Result<OAuth2ClientResource, StoreError> {
        let key = self.get_resource_key_name(domain_id, provider_id);
        let curr: StoreDataEnvelope<OAuth2ClientResource> = storage
            .get_by_key(key.as_bytes(), None)
            .await?
            .ok_or_else(|| StoreError::IO {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            })?
            .try_deserialize()?;
        let new = curr.data.with_update(data, Utc::now().timestamp());
        let new_meta = curr.metadata.new_revision();
        storage
            .set_value(
                key,
                StoreDataEnvelope {
                    data: rmp_serde::to_vec(&new)?,
                    metadata: new_meta,
                },
                None,
                Some(curr.metadata.revision),
            )
            .await?;
        Ok(new)
    }
}

/// Maps the `StoreError::IO { source }` sentinel used by `update_impl`/
/// `rotate_secret_impl`/`delete_impl` for "no such record" (constructed via
/// `std::io::Error::new(std::io::ErrorKind::NotFound, ...)`) to
/// `Oauth2ClientProviderError::NotFound`. Matches on the `io::ErrorKind`
/// directly rather than the error's `Display` string, so it can't silently
/// break if `StoreError`'s `Display` impl changes.
fn map_not_found(e: StoreError, provider_id: &str) -> Oauth2ClientProviderError {
    match e {
        StoreError::IO { source } if source.kind() == std::io::ErrorKind::NotFound => {
            Oauth2ClientProviderError::NotFound(provider_id.to_string())
        }
        e => Oauth2ClientProviderError::raft(e),
    }
}

#[async_trait]
impl Oauth2ClientBackend for RaftOauth2ClientBackend {
    #[tracing::instrument(name = "driver.raft.oauth2_client.create", level = "debug", skip_all)]
    async fn create(
        &self,
        state: &ServiceState,
        data: OAuth2ClientResourceCreate,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        match self.create_impl(raft, data).await {
            Ok(obj) => Ok(obj),
            Err(StoreError::Conflict { description, .. }) => {
                Err(Oauth2ClientProviderError::Conflict(description))
            }
            Err(e) => Err(Oauth2ClientProviderError::raft(e)),
        }
    }

    #[tracing::instrument(name = "driver.raft.oauth2_client.delete", level = "debug", skip_all, fields(domain_id = %domain_id, provider_id = %provider_id))]
    async fn delete<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.delete_impl(raft, domain_id, provider_id)
            .await
            .map_err(|e| map_not_found(e, provider_id))
    }

    #[tracing::instrument(name = "driver.raft.oauth2_client.get", level = "debug", skip_all, fields(domain_id = %domain_id, provider_id = %provider_id))]
    async fn get<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<Option<OAuth2ClientResource>, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.get_impl(raft, domain_id, provider_id)
            .await
            .map_err(Oauth2ClientProviderError::raft)
    }

    #[tracing::instrument(name = "driver.raft.oauth2_client.get_by_client_id", level = "debug", skip_all, fields(client_id = %client_id))]
    async fn get_by_client_id<'a>(
        &self,
        state: &ServiceState,
        client_id: &'a str,
    ) -> Result<Option<OAuth2ClientResource>, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.get_by_client_id_impl(raft, client_id)
            .await
            .map_err(Oauth2ClientProviderError::raft)
    }

    #[tracing::instrument(name = "driver.raft.oauth2_client.list", level = "debug", skip_all, fields(params = ?params))]
    async fn list(
        &self,
        state: &ServiceState,
        params: &OAuth2ClientResourceListParameters,
    ) -> Result<Vec<OAuth2ClientResource>, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.list_impl(raft, params)
            .await
            .map_err(Oauth2ClientProviderError::raft)
    }

    #[tracing::instrument(
        name = "driver.raft.oauth2_client.list_spiffe_clients",
        level = "debug",
        skip_all
    )]
    async fn list_spiffe_clients(
        &self,
        state: &ServiceState,
    ) -> Result<Vec<OAuth2ClientResource>, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.list_spiffe_clients_impl(raft)
            .await
            .map_err(Oauth2ClientProviderError::raft)
    }

    #[tracing::instrument(
        name = "driver.raft.oauth2_client.list_delegatable",
        level = "debug",
        skip_all
    )]
    async fn list_delegatable(
        &self,
        state: &ServiceState,
    ) -> Result<Vec<OAuth2ClientResource>, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.list_delegatable_impl(raft)
            .await
            .map_err(Oauth2ClientProviderError::raft)
    }

    #[tracing::instrument(name = "driver.raft.oauth2_client.rotate_secret", level = "debug", skip_all, fields(domain_id = %domain_id, provider_id = %provider_id))]
    async fn rotate_secret<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        client_secret_hash: String,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.rotate_secret_impl(raft, domain_id, provider_id, client_secret_hash)
            .await
            .map_err(|e| map_not_found(e, provider_id))
    }

    #[tracing::instrument(name = "driver.raft.oauth2_client.update", level = "debug", skip_all, fields(domain_id = %domain_id, provider_id = %provider_id))]
    async fn update<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        data: OAuth2ClientResourceUpdate,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.update_impl(raft, domain_id, provider_id, data)
            .await
            .map_err(|e| map_not_found(e, provider_id))
    }

    #[tracing::instrument(name = "driver.raft.oauth2_client.get_domain_settings", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn get_domain_settings<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<OAuth2DomainSettings>, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        self.get_domain_settings_impl(raft, domain_id)
            .await
            .map_err(Oauth2ClientProviderError::raft)
    }

    #[tracing::instrument(name = "driver.raft.oauth2_client.update_domain_settings", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn update_domain_settings<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        data: OAuth2DomainSettingsUpdate,
    ) -> Result<OAuth2DomainSettings, Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        match self
            .update_domain_settings_impl(raft, domain_id, data)
            .await
        {
            Ok(obj) => Ok(obj),
            Err(StoreError::Conflict { description, .. }) => {
                Err(Oauth2ClientProviderError::Conflict(description))
            }
            Err(e) => Err(Oauth2ClientProviderError::raft(e)),
        }
    }

    #[tracing::instrument(name = "driver.raft.oauth2_client.delete_domain_settings", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn delete_domain_settings<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<(), Oauth2ClientProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(Oauth2ClientProviderError::RaftNotAvailable)?;
        match self.delete_domain_settings_impl(raft, domain_id).await {
            Ok(()) => Ok(()),
            Err(StoreError::Conflict { description, .. }) => {
                Err(Oauth2ClientProviderError::Conflict(description))
            }
            Err(e) => Err(Oauth2ClientProviderError::raft(e)),
        }
    }
}

/// Linkage anchor -- see ADR-0018.
#[allow(dead_code)]
pub fn anchor() {}

inventory::submit! {
    BackendRegistration::<dyn Oauth2ClientBackend> {
        name: "raft",
        selected: |_| true,
        build: |_cfg| Box::pin(async {
            Ok(Arc::new(RaftOauth2ClientBackend::default()) as Arc<dyn Oauth2ClientBackend>)
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_distributed_storage::mock::MockStorage;
    use std::collections::HashMap;

    fn make_create(
        provider_id: &str,
        domain_id: &str,
        client_id: &str,
    ) -> OAuth2ClientResourceCreate {
        OAuth2ClientResourceCreate {
            post_logout_redirect_uris: Default::default(),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            spiffe_ids: vec![],
            delegation: None,
            client_id: client_id.to_string(),
            provider_id: provider_id.to_string(),
            domain_id: domain_id.to_string(),
            client_secret_hash: Some("$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA".to_string()),
            redirect_uris: vec!["https://rp.example.com/callback".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            grant_types: vec![GrantType::AuthorizationCode],
            require_pkce: false,
            allowed_scopes: vec!["openid".to_string()],
            pre_authorized: false,
            claims_template: HashMap::new(),
            name: "Test client".into(),
            description: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
            dpop_bound_access_tokens: false,
        }
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        let created = backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();
        assert!(created.enabled);

        let fetched = backend
            .get_impl(&storage, "domain-1", "provider-1")
            .await
            .unwrap();
        assert_eq!(fetched.unwrap().client_id, "client-1");
    }

    #[tokio::test]
    async fn test_create_duplicate_provider_id_conflicts() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();
        let result = backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-2"))
            .await;
        assert!(matches!(result, Err(StoreError::Conflict { .. })));
    }

    #[tokio::test]
    async fn test_create_duplicate_client_id_conflicts() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();
        let result = backend
            .create_impl(&storage, make_create("provider-2", "domain-1", "client-1"))
            .await;
        assert!(matches!(result, Err(StoreError::Conflict { .. })));
    }

    #[tokio::test]
    async fn test_get_by_client_id_cross_domain() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("provider-1", "domain-2", "client-1"))
            .await
            .unwrap();

        let fetched = backend
            .get_by_client_id_impl(&storage, "client-1")
            .await
            .unwrap();
        assert_eq!(fetched.unwrap().domain_id, "domain-2");

        let missing = backend
            .get_by_client_id_impl(&storage, "nonexistent")
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_list_by_domain_and_enabled_filter() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();
        backend
            .create_impl(&storage, make_create("provider-2", "domain-1", "client-2"))
            .await
            .unwrap();
        backend
            .create_impl(&storage, make_create("provider-3", "domain-2", "client-3"))
            .await
            .unwrap();

        let params = OAuth2ClientResourceListParameters {
            domain_id: "domain-1".to_string(),
            enabled: None,
            ..Default::default()
        };
        let listed = backend.list_impl(&storage, &params).await.unwrap();
        assert_eq!(listed.len(), 2);
    }

    #[tokio::test]
    async fn test_list_delegatable_across_domains() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();
        let delegation = DelegationPolicy {
            service_grants: true,
            ..Default::default()
        };

        let mut heat = make_create("heat", "infra", "client-b");
        heat.delegation = Some(delegation.clone());
        backend.create_impl(&storage, heat).await.unwrap();
        let mut local = make_create("local", "tenant", "client-a");
        local.delegation = Some(delegation.clone());
        backend.create_impl(&storage, local).await.unwrap();
        // Not a grantee: no delegation, or delegation without grants.
        backend
            .create_impl(&storage, make_create("plain", "infra", "client-c"))
            .await
            .unwrap();
        let mut obo = make_create("obo", "infra", "client-d");
        obo.delegation = Some(DelegationPolicy {
            on_behalf_of: true,
            max_operation_lifetime: Some(60),
            ..Default::default()
        });
        backend.create_impl(&storage, obo).await.unwrap();
        // Deleted grantee.
        let mut gone = make_create("gone", "infra", "client-e");
        gone.delegation = Some(delegation);
        backend.create_impl(&storage, gone).await.unwrap();
        backend
            .delete_impl(&storage, "infra", "gone")
            .await
            .unwrap();

        let listed = backend.list_delegatable_impl(&storage).await.unwrap();
        let ids: Vec<&str> = listed.iter().map(|c| c.client_id.as_str()).collect();
        assert_eq!(ids, vec!["client-a", "client-b"]);
    }

    #[tokio::test]
    async fn test_display_metadata_persisted_and_name_filter() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        let mut first = make_create("provider-1", "domain-1", "client-1");
        first.name = "Grafana Dashboard".into();
        first.logo_uri = Some("https://rp.example.com/logo.png".into());
        first.contacts = vec!["ops@example.com".into()];
        backend.create_impl(&storage, first).await.unwrap();
        let mut second = make_create("provider-2", "domain-1", "client-2");
        second.name = "CLI".into();
        backend.create_impl(&storage, second).await.unwrap();

        let fetched = backend
            .get_impl(&storage, "domain-1", "provider-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.name, "Grafana Dashboard");
        assert_eq!(fetched.contacts, vec!["ops@example.com".to_string()]);

        let params = OAuth2ClientResourceListParameters {
            domain_id: "domain-1".to_string(),
            name: Some("grafana".to_string()),
            ..Default::default()
        };
        let listed = backend.list_impl(&storage, &params).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].provider_id, "provider-1");

        let updated = backend
            .update_impl(
                &storage,
                "domain-1",
                "provider-1",
                OAuth2ClientResourceUpdate {
                    name: Some("Grafana".into()),
                    logo_uri: Some(String::new()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.name, "Grafana");
        assert_eq!(updated.logo_uri, None);
    }

    #[tokio::test]
    async fn test_domain_settings_lifecycle() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        assert!(
            backend
                .get_domain_settings_impl(&storage, "domain-1")
                .await
                .unwrap()
                .is_none()
        );

        let update = |dpop| OAuth2DomainSettingsUpdate { dpop };
        let created = backend
            .update_domain_settings_impl(&storage, "domain-1", update(Some(DpopMode::Optional)))
            .await
            .unwrap();
        assert_eq!(created.dpop, DpopMode::Optional);
        assert_eq!(
            backend
                .get_domain_settings_impl(&storage, "domain-1")
                .await
                .unwrap()
                .unwrap(),
            created
        );

        // An empty update keeps the mode; a later one replaces it.
        let kept = backend
            .update_domain_settings_impl(&storage, "domain-1", update(None))
            .await
            .unwrap();
        assert_eq!(kept.dpop, DpopMode::Optional);
        let raised = backend
            .update_domain_settings_impl(&storage, "domain-1", update(Some(DpopMode::Required)))
            .await
            .unwrap();
        assert_eq!(raised.dpop, DpopMode::Required);

        // Other domains are unaffected.
        assert!(
            backend
                .get_domain_settings_impl(&storage, "domain-2")
                .await
                .unwrap()
                .is_none()
        );

        backend
            .delete_domain_settings_impl(&storage, "domain-1")
            .await
            .unwrap();
        assert!(
            backend
                .get_domain_settings_impl(&storage, "domain-1")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_domain_settings_empty_update_writes_nothing() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        let unchanged = backend
            .update_domain_settings_impl(
                &storage,
                "domain-1",
                OAuth2DomainSettingsUpdate::default(),
            )
            .await
            .unwrap();
        assert_eq!(unchanged, OAuth2DomainSettings::default_for("domain-1"));
        assert!(
            backend
                .get_domain_settings_impl(&storage, "domain-1")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A writer holding a stale view must not overwrite a newer record, and
    /// a create must not overwrite a record that appeared meanwhile.
    #[tokio::test]
    async fn test_domain_settings_conflicts() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();
        let key = backend.get_domain_settings_key_name("domain-1");
        let update = |dpop| OAuth2DomainSettingsUpdate { dpop: Some(dpop) };

        // The record appears between the read and the write of a create.
        let stale = OAuth2DomainSettings::default_for("domain-1")
            .with_update(update(DpopMode::Optional), 1);
        let create = || {
            Mutation::create_if_absent(key.clone(), &stale, Metadata::new(), None::<&str>).unwrap()
        };
        storage.transaction(vec![create()]).await.unwrap();
        let res = require_no_conflict(storage.transaction(vec![create()]).await, || {
            StoreError::Conflict {
                subject: key.clone(),
                description: String::new(),
            }
        });
        assert!(matches!(res, Err(StoreError::Conflict { .. })));

        // A revision-guarded set and remove fail on a stale revision.
        let rev = storage
            .get_by_key(key.as_bytes(), None)
            .await
            .unwrap()
            .unwrap()
            .metadata
            .revision;
        backend
            .update_domain_settings_impl(&storage, "domain-1", update(DpopMode::Required))
            .await
            .unwrap();
        let stale_set = Mutation::set(
            key.clone(),
            &stale,
            Metadata::new(),
            None::<&str>,
            Some(rev),
        )
        .unwrap();
        let res = require_no_conflict(storage.transaction(vec![stale_set]).await, || {
            StoreError::Conflict {
                subject: key.clone(),
                description: String::new(),
            }
        });
        assert!(matches!(res, Err(StoreError::Conflict { .. })));
        let stale_remove = Mutation::remove(key.clone(), None::<&str>, Some(rev));
        let res = require_no_conflict(storage.transaction(vec![stale_remove]).await, || {
            StoreError::Conflict {
                subject: key.clone(),
                description: String::new(),
            }
        });
        assert!(matches!(res, Err(StoreError::Conflict { .. })));
        assert_eq!(
            backend
                .get_domain_settings_impl(&storage, "domain-1")
                .await
                .unwrap()
                .unwrap()
                .dpop,
            DpopMode::Required
        );
    }

    #[tokio::test]
    async fn test_dpop_bound_access_tokens_persisted_and_updated() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        let created = backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();
        assert!(!created.dpop_bound_access_tokens);

        let mut bound = make_create("provider-2", "domain-1", "client-2");
        bound.dpop_bound_access_tokens = true;
        let created = backend.create_impl(&storage, bound).await.unwrap();
        assert!(created.dpop_bound_access_tokens);

        let update = |value| OAuth2ClientResourceUpdate {
            dpop_bound_access_tokens: value,
            ..Default::default()
        };
        // `None` leaves the flag unchanged.
        let unchanged = backend
            .update_impl(&storage, "domain-1", "provider-2", update(None))
            .await
            .unwrap();
        assert!(unchanged.dpop_bound_access_tokens);
        let off = backend
            .update_impl(&storage, "domain-1", "provider-2", update(Some(false)))
            .await
            .unwrap();
        assert!(!off.dpop_bound_access_tokens);
        let on = backend
            .update_impl(&storage, "domain-1", "provider-1", update(Some(true)))
            .await
            .unwrap();
        assert!(on.dpop_bound_access_tokens);
    }

    #[test]
    fn test_record_without_display_fields_deserializes() {
        // Records are stored as positional MessagePack arrays; one written
        // before the display fields existed is shorter and must still load.
        #[derive(serde::Serialize)]
        struct Legacy(
            String,
            String,
            String,
            Option<String>,
            Vec<String>,
            String,
            Vec<GrantType>,
            bool,
            Vec<String>,
            bool,
            bool,
            HashMap<String, String>,
            i64,
            i64,
            Option<i64>,
        );
        let legacy = Legacy(
            "cid".into(),
            "prov".into(),
            "dom".into(),
            None,
            vec![],
            "none".into(),
            vec![],
            true,
            vec![],
            false,
            true,
            HashMap::new(),
            1,
            2,
            None,
        );
        let bytes = rmp_serde::to_vec(&legacy).unwrap();
        let parsed: OAuth2ClientResource = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed.client_id, "cid");
        assert_eq!(parsed.name, "");
        assert!(parsed.contacts.is_empty());
        assert_eq!(parsed.display_name(), "prov");
        assert!(parsed.spiffe_ids.is_empty());
        assert!(parsed.delegation.is_none());
    }

    #[tokio::test]
    async fn test_list_spiffe_clients_spans_domains() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        for (domain, provider) in [("domain-1", "provider-1"), ("domain-2", "provider-2")] {
            let mut create = make_create(provider, domain, &format!("client-{provider}"));
            create.token_endpoint_auth_method = "tls_client_auth".into();
            create.spiffe_ids = vec![format!("spiffe://cloud.example/ns/{provider}")];
            backend.create_impl(&storage, create).await.unwrap();
        }
        // No SPIFFE IDs: not listed.
        backend
            .create_impl(&storage, make_create("provider-3", "domain-1", "client-3"))
            .await
            .unwrap();

        let listed = backend.list_spiffe_clients_impl(&storage).await.unwrap();
        assert_eq!(listed.len(), 2);
    }

    #[tokio::test]
    async fn test_delegation_persisted_and_removed() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        let mut create = make_create("provider-1", "domain-1", "client-1");
        create.token_endpoint_auth_method = "tls_client_auth".into();
        create.spiffe_ids = vec!["spiffe://cloud.example/ns/nova/sa/*".into()];
        create.delegation = Some(DelegationPolicy {
            service_grants: true,
            cross_domain: true,
            max_role_ids: vec!["member".into()],
            max_grant_lifetime: Some(3600),
            ..Default::default()
        });
        backend.create_impl(&storage, create.clone()).await.unwrap();

        let fetched = backend
            .get_by_client_id_impl(&storage, "client-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.spiffe_ids, create.spiffe_ids);
        assert_eq!(fetched.delegation, create.delegation);

        let updated = backend
            .update_impl(
                &storage,
                "domain-1",
                "provider-1",
                OAuth2ClientResourceUpdate {
                    remove_delegation: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(updated.delegation.is_none());
        assert_eq!(updated.spiffe_ids, create.spiffe_ids);
    }

    #[tokio::test]
    async fn test_update() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();

        let update = OAuth2ClientResourceUpdate {
            enabled: Some(false),
            ..Default::default()
        };
        let updated = backend
            .update_impl(&storage, "domain-1", "provider-1", update)
            .await
            .unwrap();
        assert!(!updated.enabled);
    }

    #[tokio::test]
    async fn test_rotate_secret() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();

        let updated = backend
            .rotate_secret_impl(&storage, "domain-1", "provider-1", "new-hash".to_string())
            .await
            .unwrap();
        assert_eq!(updated.client_secret_hash, Some("new-hash".to_string()));
    }

    #[tokio::test]
    async fn test_soft_delete_leaves_record_gettable_disabled() {
        let backend = RaftOauth2ClientBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("provider-1", "domain-1", "client-1"))
            .await
            .unwrap();

        let deleted = backend
            .delete_impl(&storage, "domain-1", "provider-1")
            .await
            .unwrap();
        assert!(!deleted.enabled);
        assert!(deleted.deleted_at.is_some());

        let fetched = backend
            .get_impl(&storage, "domain-1", "provider-1")
            .await
            .unwrap();
        assert!(fetched.is_some());
        assert!(!fetched.unwrap().enabled);
    }
}
