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
//! # OpenStack Keystone Raft driver for the SCIM realm provider (ADR 0024).
use async_trait::async_trait;
use chrono::Utc;

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::scim_realm::backend::ScimRealmBackend;
use openstack_keystone_core::scim_realm::error::ScimRealmProviderError;
use openstack_keystone_core::scim_resource::backend::ScimResourceBackend;
use openstack_keystone_core::scim_resource::error::ScimResourceProviderError;
use openstack_keystone_core_types::scim::*;
use openstack_keystone_distributed_storage::{
    Metadata, StorageApi, StoreDataEnvelope, StoreError, store_command::Mutation,
};

/// Raft Database SCIM realm backend.
///
/// Realms are indexed directly by their `(domain_id, provider_id)`
/// coordinate (ADR 0024 §2.A) — no secondary lookup index is needed since
/// both dimensions are always known before a realm lookup is performed (the
/// Realm Activation Gate, ADR 0024 §2.B, resolves both from the
/// authenticated `ApiClientResource` before consulting this backend).
#[derive(Default)]
pub struct RaftBackend {}

impl RaftBackend {
    /// Primary storage key: `scim_realm:v1:<domain_id>:<provider_id>`.
    fn get_realm_key_name<D: AsRef<str>, P: AsRef<str>>(
        &self,
        domain_id: D,
        provider_id: P,
    ) -> String {
        format!(
            "scim_realm:v1:{}:{}",
            domain_id.as_ref(),
            provider_id.as_ref()
        )
    }

    /// Prefix covering all realms for a domain (used for listing).
    fn get_realm_by_domain_prefix<D: AsRef<str>>(&self, domain_id: D) -> String {
        format!("scim_realm:v1:{}:", domain_id.as_ref())
    }

    /// Primary storage key for a SCIM resource ownership anchor: `scim_
    /// resource:v1:<domain_id>:<provider_id>:<type>:<keystone_id>` (ADR 0024
    /// §3.B).
    fn get_resource_key_name<D: AsRef<str>, P: AsRef<str>, K: AsRef<str>>(
        &self,
        domain_id: D,
        provider_id: P,
        resource_type: ScimResourceType,
        keystone_id: K,
    ) -> String {
        format!(
            "scim_resource:v1:{}:{}:{}:{}",
            domain_id.as_ref(),
            provider_id.as_ref(),
            resource_type,
            keystone_id.as_ref()
        )
    }

    /// Prefix covering all anchors owned by a realm for a resource type
    /// (used for listing).
    fn get_resource_by_realm_type_prefix<D: AsRef<str>, P: AsRef<str>>(
        &self,
        domain_id: D,
        provider_id: P,
        resource_type: ScimResourceType,
    ) -> String {
        format!(
            "scim_resource:v1:{}:{}:{}:",
            domain_id.as_ref(),
            provider_id.as_ref(),
            resource_type
        )
    }

    /// Realm-scoped `externalId` claim key: `scim_resource:external_id_
    /// claim:v1:<domain_id>:<provider_id>:<type>:<external_id>` → value:
    /// `keystone_id`. Written with `Mutation::create_if_absent` so a second
    /// concurrent create for the same `externalId` within the same realm
    /// fails the claim instead of racing (ADR 0024 §3.D's TOCTOU concern,
    /// closed here for the realm-scoped dimension of the check — the
    /// domain-wide cross-realm `userName` check is a live query against
    /// core Identity, which owns a legacy SQL schema this crate does not
    /// control, so it remains best-effort; see `find_user_by_name_ci`).
    fn get_external_id_claim_key_name<D: AsRef<str>, P: AsRef<str>, E: AsRef<str>>(
        &self,
        domain_id: D,
        provider_id: P,
        resource_type: ScimResourceType,
        external_id: E,
    ) -> String {
        format!(
            "scim_resource:external_id_claim:v1:{}:{}:{}:{}",
            domain_id.as_ref(),
            provider_id.as_ref(),
            resource_type,
            external_id.as_ref()
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn create_impl(
        &self,
        storage: &dyn StorageApi,
        data: ScimRealmResourceCreate,
    ) -> Result<ScimRealmResource, StoreError> {
        let now = Utc::now().timestamp();
        let obj = ScimRealmResource {
            domain_id: data.domain_id,
            provider_id: data.provider_id,
            idp_id: data.idp_id,
            display_name: data.display_name,
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        let mutations = vec![Mutation::set(
            self.get_realm_key_name(&obj.domain_id, &obj.provider_id),
            obj.clone(),
            Metadata::new(),
            None::<&str>,
            None,
        )?];
        storage.transaction(mutations).await?;
        Ok(obj)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn get_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        provider_id: &str,
    ) -> Result<Option<ScimRealmResource>, StoreError> {
        Ok(storage
            .get_by_key(
                self.get_realm_key_name(domain_id, provider_id).as_bytes(),
                None,
            )
            .await?
            .map(|env| env.try_deserialize::<ScimRealmResource>())
            .transpose()?
            .map(|x| x.data))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn list_impl(
        &self,
        storage: &dyn StorageApi,
        params: &ScimRealmResourceListParameters,
    ) -> Result<Vec<ScimRealmResource>, StoreError> {
        let prefix = self.get_realm_by_domain_prefix(&params.domain_id);
        let mut res: Vec<ScimRealmResource> = Vec::new();
        for (_, envelope) in storage.prefix(prefix.as_bytes(), None).await? {
            let candidate = envelope.try_deserialize::<ScimRealmResource>()?.data;
            if let Some(enabled) = params.enabled
                && candidate.enabled != enabled
            {
                continue;
            }
            res.push(candidate);
        }
        Ok(res)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn update_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        provider_id: &str,
        data: ScimRealmResourceUpdate,
    ) -> Result<ScimRealmResource, StoreError> {
        let key = self.get_realm_key_name(domain_id, provider_id);
        let curr: StoreDataEnvelope<ScimRealmResource> = storage
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

#[async_trait]
impl ScimRealmBackend for RaftBackend {
    async fn create(
        &self,
        state: &ServiceState,
        data: ScimRealmResourceCreate,
    ) -> Result<ScimRealmResource, ScimRealmProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ScimRealmProviderError::RaftNotAvailable)?;
        self.create_impl(raft, data)
            .await
            .map_err(ScimRealmProviderError::raft)
    }

    async fn get<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<Option<ScimRealmResource>, ScimRealmProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ScimRealmProviderError::RaftNotAvailable)?;
        self.get_impl(raft, domain_id, provider_id)
            .await
            .map_err(ScimRealmProviderError::raft)
    }

    async fn list(
        &self,
        state: &ServiceState,
        params: &ScimRealmResourceListParameters,
    ) -> Result<Vec<ScimRealmResource>, ScimRealmProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ScimRealmProviderError::RaftNotAvailable)?;
        self.list_impl(raft, params)
            .await
            .map_err(ScimRealmProviderError::raft)
    }

    async fn update<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        data: ScimRealmResourceUpdate,
    ) -> Result<ScimRealmResource, ScimRealmProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ScimRealmProviderError::RaftNotAvailable)?;
        match self.update_impl(raft, domain_id, provider_id, data).await {
            Ok(obj) => Ok(obj),
            Err(e) => {
                if e.to_string().contains("NotFound") {
                    Err(ScimRealmProviderError::NotFound(provider_id.to_string()))
                } else {
                    Err(ScimRealmProviderError::raft(e))
                }
            }
        }
    }
}

impl RaftBackend {
    /// Best-effort release of an `externalId` claim, used to compensate for
    /// a primary-index write failing after the claim already committed.
    /// Best-effort: this runs on an already-failing path, so a failure here
    /// is logged, not propagated -- the caller returns the original error
    /// either way, and a leaked claim is recoverable by an operator, whereas
    /// masking the original error is not.
    async fn release_external_id_claim(&self, storage: &dyn StorageApi, claim_key: Option<String>) {
        let Some(key) = claim_key else { return };
        if let Err(e) = storage
            .transaction(vec![Mutation::remove(key.clone(), None::<&str>, None)])
            .await
        {
            tracing::warn!(
                claim_key = %key,
                error = %e,
                "failed to release orphaned externalId claim after primary index write failure"
            );
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn create_resource_impl(
        &self,
        storage: &dyn StorageApi,
        data: ScimResourceIndexCreate,
    ) -> Result<ScimResourceIndex, StoreError> {
        let now = Utc::now().timestamp();
        let obj = ScimResourceIndex {
            domain_id: data.domain_id,
            provider_id: data.provider_id,
            resource_type: data.resource_type,
            keystone_id: data.keystone_id,
            external_id: data.external_id,
            version: 0,
            deprovisioned_at: None,
            created_at: now,
            updated_at: now,
        };

        // Claim the realm-scoped `externalId` first (if present) via
        // `create_if_absent`, in its own transaction, so a concurrent
        // create for the same `externalId` within this realm fails the
        // claim rather than racing (ADR 0024 §3.D).
        let mut claim_key = None;
        if let Some(ref eid) = obj.external_id {
            let key = self.get_external_id_claim_key_name(
                &obj.domain_id,
                &obj.provider_id,
                obj.resource_type,
                eid,
            );
            let response = storage
                .transaction(vec![Mutation::create_if_absent(
                    key.clone(),
                    obj.keystone_id.clone(),
                    Metadata::new(),
                    None::<&str>,
                )?])
                .await?;
            if !response.violations.is_empty() {
                return Err(StoreError::Conflict {
                    subject: key,
                    description: "externalId already claimed within this realm".to_string(),
                });
            }
            claim_key = Some(key);
        }

        let primary_write = storage
            .transaction(vec![Mutation::set(
                self.get_resource_key_name(
                    &obj.domain_id,
                    &obj.provider_id,
                    obj.resource_type,
                    &obj.keystone_id,
                ),
                obj.clone(),
                Metadata::new(),
                None::<&str>,
                None,
            )?])
            .await;

        // The primary write can fail (transport error, or -- in principle --
        // a violation) after the `externalId` claim above already committed.
        // Without releasing it here, the claim would be orphaned: it points
        // at an index record that was never written, permanently blocking
        // reuse of this `externalId` within the realm (nothing else ever
        // deletes a claim except a successful update/delete of the resource
        // it's supposed to belong to).
        match primary_write {
            Ok(response) if response.violations.is_empty() => Ok(obj),
            Ok(response) => {
                self.release_external_id_claim(storage, claim_key).await;
                Err(StoreError::Conflict {
                    subject: response
                        .violations
                        .first()
                        .map(|v| v.subject.clone())
                        .unwrap_or_default(),
                    description: "failed to persist SCIM resource index".to_string(),
                })
            }
            Err(e) => {
                self.release_external_id_claim(storage, claim_key).await;
                Err(e.into())
            }
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn get_resource_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        provider_id: &str,
        resource_type: ScimResourceType,
        keystone_id: &str,
    ) -> Result<Option<ScimResourceIndex>, StoreError> {
        Ok(storage
            .get_by_key(
                self.get_resource_key_name(domain_id, provider_id, resource_type, keystone_id)
                    .as_bytes(),
                None,
            )
            .await?
            .map(|env| env.try_deserialize::<ScimResourceIndex>())
            .transpose()?
            .map(|x| x.data))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn get_resource_by_external_id_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        provider_id: &str,
        resource_type: ScimResourceType,
        external_id: &str,
    ) -> Result<Option<ScimResourceIndex>, StoreError> {
        let claim_key =
            self.get_external_id_claim_key_name(domain_id, provider_id, resource_type, external_id);
        let Some(env) = storage.get_by_key(claim_key.as_bytes(), None).await? else {
            return Ok(None);
        };
        let keystone_id = env.try_deserialize::<String>()?.data;
        self.get_resource_impl(storage, domain_id, provider_id, resource_type, &keystone_id)
            .await
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn list_resource_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        provider_id: &str,
        resource_type: ScimResourceType,
    ) -> Result<Vec<ScimResourceIndex>, StoreError> {
        let prefix = self.get_resource_by_realm_type_prefix(domain_id, provider_id, resource_type);
        let mut res: Vec<ScimResourceIndex> = Vec::new();
        for (_, envelope) in storage.prefix(prefix.as_bytes(), None).await? {
            res.push(envelope.try_deserialize::<ScimResourceIndex>()?.data);
        }
        Ok(res)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn update_resource_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        provider_id: &str,
        resource_type: ScimResourceType,
        keystone_id: &str,
        data: ScimResourceIndexUpdate,
    ) -> Result<ScimResourceIndex, StoreError> {
        let key = self.get_resource_key_name(domain_id, provider_id, resource_type, keystone_id);
        let curr: StoreDataEnvelope<ScimResourceIndex> = storage
            .get_by_key(key.as_bytes(), None)
            .await?
            .ok_or_else(|| StoreError::IO {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            })?
            .try_deserialize()?;

        // Re-claim `externalId` before persisting, if it changed: release
        // the old claim (if any) and atomically claim the new one so two
        // concurrent updates can't both succeed onto the same new
        // `externalId` within this realm.
        if let Some(ref new_eid) = data.external_id
            && new_eid != &curr.data.external_id
        {
            if let Some(ref old_eid) = curr.data.external_id {
                let old_claim_key = self.get_external_id_claim_key_name(
                    domain_id,
                    provider_id,
                    resource_type,
                    old_eid,
                );
                storage
                    .transaction(vec![Mutation::remove(old_claim_key, None::<&str>, None)])
                    .await?;
            }
            if let Some(eid) = new_eid {
                let claim_key =
                    self.get_external_id_claim_key_name(domain_id, provider_id, resource_type, eid);
                let response = storage
                    .transaction(vec![Mutation::create_if_absent(
                        claim_key.clone(),
                        keystone_id.to_string(),
                        Metadata::new(),
                        None::<&str>,
                    )?])
                    .await?;
                if !response.violations.is_empty() {
                    return Err(StoreError::Conflict {
                        subject: claim_key,
                        description: "externalId already claimed within this realm".to_string(),
                    });
                }
            }
        }

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

#[async_trait]
impl ScimResourceBackend for RaftBackend {
    async fn create(
        &self,
        state: &ServiceState,
        data: ScimResourceIndexCreate,
    ) -> Result<ScimResourceIndex, ScimResourceProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ScimResourceProviderError::RaftNotAvailable)?;
        match self.create_resource_impl(raft, data).await {
            Ok(obj) => Ok(obj),
            Err(StoreError::Conflict { description, .. }) => {
                Err(ScimResourceProviderError::Conflict(description))
            }
            Err(e) => Err(ScimResourceProviderError::raft(e)),
        }
    }

    async fn get<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
        keystone_id: &'a str,
    ) -> Result<Option<ScimResourceIndex>, ScimResourceProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ScimResourceProviderError::RaftNotAvailable)?;
        self.get_resource_impl(raft, domain_id, provider_id, resource_type, keystone_id)
            .await
            .map_err(ScimResourceProviderError::raft)
    }

    async fn get_by_external_id<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
        external_id: &'a str,
    ) -> Result<Option<ScimResourceIndex>, ScimResourceProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ScimResourceProviderError::RaftNotAvailable)?;
        self.get_resource_by_external_id_impl(
            raft,
            domain_id,
            provider_id,
            resource_type,
            external_id,
        )
        .await
        .map_err(ScimResourceProviderError::raft)
    }

    async fn list<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
    ) -> Result<Vec<ScimResourceIndex>, ScimResourceProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ScimResourceProviderError::RaftNotAvailable)?;
        self.list_resource_impl(raft, domain_id, provider_id, resource_type)
            .await
            .map_err(ScimResourceProviderError::raft)
    }

    async fn update<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        resource_type: ScimResourceType,
        keystone_id: &'a str,
        data: ScimResourceIndexUpdate,
    ) -> Result<ScimResourceIndex, ScimResourceProviderError> {
        let raft = state
            .storage
            .as_deref()
            .ok_or(ScimResourceProviderError::RaftNotAvailable)?;
        match self
            .update_resource_impl(
                raft,
                domain_id,
                provider_id,
                resource_type,
                keystone_id,
                data,
            )
            .await
        {
            Ok(obj) => Ok(obj),
            Err(StoreError::Conflict { description, .. }) => {
                Err(ScimResourceProviderError::Conflict(description))
            }
            Err(e) => {
                if e.to_string().contains("NotFound") {
                    Err(ScimResourceProviderError::NotFound(keystone_id.to_string()))
                } else {
                    Err(ScimResourceProviderError::raft(e))
                }
            }
        }
    }
}

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_distributed_storage::ApiStoreError;
    use openstack_keystone_distributed_storage::mock::MockStorage;

    fn make_create(domain_id: &str, provider_id: &str) -> ScimRealmResourceCreate {
        ScimRealmResourceCreate {
            domain_id: domain_id.to_string(),
            provider_id: provider_id.to_string(),
            idp_id: "idp-1".to_string(),
            display_name: "Okta - Employees".to_string(),
        }
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let created = backend
            .create_impl(&storage, make_create("domain-1", "provider-1"))
            .await
            .unwrap();
        assert!(created.enabled);

        let fetched = backend
            .get_impl(&storage, "domain-1", "provider-1")
            .await
            .unwrap();
        assert_eq!(fetched.unwrap().display_name, "Okta - Employees");
    }

    #[tokio::test]
    async fn test_get_missing_returns_none() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let fetched = backend
            .get_impl(&storage, "domain-1", "nonexistent")
            .await
            .unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn test_list_by_domain_and_enabled_filter() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("domain-1", "provider-1"))
            .await
            .unwrap();
        backend
            .create_impl(&storage, make_create("domain-1", "provider-2"))
            .await
            .unwrap();
        backend
            .create_impl(&storage, make_create("domain-2", "provider-3"))
            .await
            .unwrap();

        let params = ScimRealmResourceListParameters {
            domain_id: "domain-1".to_string(),
            enabled: None,
        };
        let listed = backend.list_impl(&storage, &params).await.unwrap();
        assert_eq!(listed.len(), 2);

        backend
            .update_impl(
                &storage,
                "domain-1",
                "provider-1",
                ScimRealmResourceUpdate {
                    idp_id: None,
                    display_name: None,
                    enabled: Some(false),
                },
            )
            .await
            .unwrap();

        let params_enabled = ScimRealmResourceListParameters {
            domain_id: "domain-1".to_string(),
            enabled: Some(true),
        };
        let listed_enabled = backend.list_impl(&storage, &params_enabled).await.unwrap();
        assert_eq!(listed_enabled.len(), 1);
        assert_eq!(listed_enabled[0].provider_id, "provider-2");
    }

    #[tokio::test]
    async fn test_update_disables_realm() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_impl(&storage, make_create("domain-1", "provider-1"))
            .await
            .unwrap();

        let updated = backend
            .update_impl(
                &storage,
                "domain-1",
                "provider-1",
                ScimRealmResourceUpdate {
                    idp_id: None,
                    display_name: None,
                    enabled: Some(false),
                },
            )
            .await
            .unwrap();
        assert!(!updated.enabled);

        let fetched = backend
            .get_impl(&storage, "domain-1", "provider-1")
            .await
            .unwrap()
            .unwrap();
        assert!(!fetched.enabled);
    }

    #[tokio::test]
    async fn test_update_missing_realm_errors() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let result = backend
            .update_impl(
                &storage,
                "domain-1",
                "nonexistent",
                ScimRealmResourceUpdate {
                    idp_id: None,
                    display_name: None,
                    enabled: Some(false),
                },
            )
            .await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------
    // ScimResourceIndex (ADR 0024 §3.A) tests
    // -----------------------------------------------------------------

    fn make_resource_create(
        domain_id: &str,
        provider_id: &str,
        keystone_id: &str,
        external_id: Option<&str>,
    ) -> ScimResourceIndexCreate {
        ScimResourceIndexCreate {
            domain_id: domain_id.to_string(),
            provider_id: provider_id.to_string(),
            resource_type: ScimResourceType::User,
            keystone_id: keystone_id.to_string(),
            external_id: external_id.map(|s| s.to_string()),
        }
    }

    /// `StorageApi` wrapper that fails the `nth` call to `transaction`
    /// (1-indexed) with an IO error, delegating everything else to the
    /// inner `MockStorage`. Used to simulate the primary-index write failing
    /// *after* the `externalId` claim's own transaction already committed.
    struct FailingNthTransactionStorage {
        inner: MockStorage,
        nth: usize,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl StorageApi for FailingNthTransactionStorage {
        async fn contains_key(
            &self,
            key: &[u8],
            keyspace: Option<&str>,
        ) -> Result<bool, ApiStoreError> {
            self.inner.contains_key(key, keyspace).await
        }

        async fn get_by_key(
            &self,
            key: &[u8],
            keyspace: Option<&str>,
        ) -> Result<Option<StoreDataEnvelope<Vec<u8>>>, ApiStoreError> {
            self.inner.get_by_key(key, keyspace).await
        }

        async fn prefix(
            &self,
            prefix: &[u8],
            keyspace: Option<&str>,
        ) -> Result<Vec<(String, StoreDataEnvelope<Vec<u8>>)>, ApiStoreError> {
            self.inner.prefix(prefix, keyspace).await
        }

        async fn prefix_index(&self, prefix: &[u8]) -> Result<Vec<String>, ApiStoreError> {
            self.inner.prefix_index(prefix).await
        }

        async fn remove(
            &self,
            key: String,
            keyspace: Option<String>,
        ) -> Result<openstack_keystone_distributed_storage::StoreResponse, ApiStoreError> {
            self.inner.remove(key, keyspace).await
        }

        async fn remove_index(
            &self,
            key: String,
        ) -> Result<openstack_keystone_distributed_storage::StoreResponse, ApiStoreError> {
            self.inner.remove_index(key).await
        }

        async fn set_value(
            &self,
            key: String,
            value: StoreDataEnvelope<Vec<u8>>,
            keyspace: Option<String>,
            expected_revision: Option<u64>,
        ) -> Result<openstack_keystone_distributed_storage::StoreResponse, ApiStoreError> {
            self.inner
                .set_value(key, value, keyspace, expected_revision)
                .await
        }

        async fn set_index_key(
            &self,
            key: String,
        ) -> Result<openstack_keystone_distributed_storage::StoreResponse, ApiStoreError> {
            self.inner.set_index_key(key).await
        }

        async fn transaction(
            &self,
            mutations: Vec<Mutation>,
        ) -> Result<openstack_keystone_distributed_storage::StoreResponse, ApiStoreError> {
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if call == self.nth {
                return Err(ApiStoreError::other(std::io::Error::other(
                    "simulated primary write failure",
                )));
            }
            self.inner.transaction(mutations).await
        }

        async fn is_initialized(&self) -> Result<bool, ApiStoreError> {
            self.inner.is_initialized().await
        }

        async fn initialize(
            &self,
            nodes: std::collections::HashMap<u64, openstack_keystone_distributed_storage::Node>,
        ) -> Result<(), ApiStoreError> {
            self.inner.initialize(nodes).await
        }

        async fn current_leader(&self) -> Option<u64> {
            self.inner.current_leader().await
        }

        async fn keyspace_exists(&self, keyspace: &str) -> Result<bool, ApiStoreError> {
            self.inner.keyspace_exists(keyspace).await
        }

        async fn drop_keyspace(&self, keyspace: &str) -> Result<(), ApiStoreError> {
            self.inner.drop_keyspace(keyspace).await
        }

        async fn node_id(&self) -> u64 {
            self.inner.node_id().await
        }
    }

    #[tokio::test]
    async fn test_create_resource_releases_claim_when_primary_write_fails() {
        let backend = RaftBackend::default();
        // 1st `transaction` call claims the externalId; 2nd is the primary
        // index write, which this storage fails.
        let storage = FailingNthTransactionStorage {
            inner: MockStorage::default(),
            nth: 2,
            calls: std::sync::atomic::AtomicUsize::new(0),
        };

        let result = backend
            .create_resource_impl(
                &storage,
                make_resource_create("domain-1", "provider-1", "user-1", Some("ext-1")),
            )
            .await;
        assert!(result.is_err());

        // The claim must have been released: a retry with the same
        // `externalId` (against a storage that doesn't fail this time)
        // succeeds instead of permanently conflicting.
        let retry = backend
            .create_resource_impl(
                &storage.inner,
                make_resource_create("domain-1", "provider-1", "user-2", Some("ext-1")),
            )
            .await;
        assert!(retry.is_ok());
    }

    #[tokio::test]
    async fn test_create_and_get_resource_index() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let created = backend
            .create_resource_impl(
                &storage,
                make_resource_create("domain-1", "provider-1", "user-1", Some("ext-1")),
            )
            .await
            .unwrap();
        assert_eq!(created.version, 0);
        assert!(created.deprovisioned_at.is_none());

        let fetched = backend
            .get_resource_impl(
                &storage,
                "domain-1",
                "provider-1",
                ScimResourceType::User,
                "user-1",
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.keystone_id, "user-1");
        assert_eq!(fetched.external_id.as_deref(), Some("ext-1"));
    }

    #[tokio::test]
    async fn test_get_resource_index_missing_returns_none() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let fetched = backend
            .get_resource_impl(
                &storage,
                "domain-1",
                "provider-1",
                ScimResourceType::User,
                "nonexistent",
            )
            .await
            .unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn test_get_resource_by_external_id() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_resource_impl(
                &storage,
                make_resource_create("domain-1", "provider-1", "user-1", Some("ext-1")),
            )
            .await
            .unwrap();

        let fetched = backend
            .get_resource_by_external_id_impl(
                &storage,
                "domain-1",
                "provider-1",
                ScimResourceType::User,
                "ext-1",
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.keystone_id, "user-1");

        let missing = backend
            .get_resource_by_external_id_impl(
                &storage,
                "domain-1",
                "provider-1",
                ScimResourceType::User,
                "nonexistent",
            )
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_create_resource_duplicate_external_id_within_realm_conflicts() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_resource_impl(
                &storage,
                make_resource_create("domain-1", "provider-1", "user-1", Some("ext-1")),
            )
            .await
            .unwrap();

        let result = backend
            .create_resource_impl(
                &storage,
                make_resource_create("domain-1", "provider-1", "user-2", Some("ext-1")),
            )
            .await;
        assert!(matches!(result, Err(StoreError::Conflict { .. })));

        // The second create's primary record must not have been persisted:
        // the claim transaction runs first and its violation short-circuits
        // `create_resource_impl` before the primary write is even attempted.
        let fetched = backend
            .get_resource_impl(
                &storage,
                "domain-1",
                "provider-1",
                ScimResourceType::User,
                "user-2",
            )
            .await
            .unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn test_create_resource_same_external_id_different_realm_allowed() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_resource_impl(
                &storage,
                make_resource_create("domain-1", "provider-1", "user-1", Some("ext-1")),
            )
            .await
            .unwrap();

        let created = backend
            .create_resource_impl(
                &storage,
                make_resource_create("domain-1", "provider-2", "user-2", Some("ext-1")),
            )
            .await
            .unwrap();
        assert_eq!(created.keystone_id, "user-2");
    }

    #[tokio::test]
    async fn test_list_resource_index_scoped_to_realm_and_type() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_resource_impl(
                &storage,
                make_resource_create("domain-1", "provider-1", "user-1", None),
            )
            .await
            .unwrap();
        backend
            .create_resource_impl(
                &storage,
                make_resource_create("domain-1", "provider-1", "user-2", None),
            )
            .await
            .unwrap();
        backend
            .create_resource_impl(
                &storage,
                make_resource_create("domain-1", "provider-2", "user-3", None),
            )
            .await
            .unwrap();

        let listed = backend
            .list_resource_impl(&storage, "domain-1", "provider-1", ScimResourceType::User)
            .await
            .unwrap();
        assert_eq!(listed.len(), 2);

        let listed_group = backend
            .list_resource_impl(&storage, "domain-1", "provider-1", ScimResourceType::Group)
            .await
            .unwrap();
        assert!(listed_group.is_empty());
    }

    #[tokio::test]
    async fn test_update_resource_soft_disable() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_resource_impl(
                &storage,
                make_resource_create("domain-1", "provider-1", "user-1", None),
            )
            .await
            .unwrap();

        let updated = backend
            .update_resource_impl(
                &storage,
                "domain-1",
                "provider-1",
                ScimResourceType::User,
                "user-1",
                ScimResourceIndexUpdate {
                    external_id: None,
                    deprovisioned_at: Some(Some(12345)),
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.deprovisioned_at, Some(12345));
        assert_eq!(updated.version, 1);
    }

    #[tokio::test]
    async fn test_update_resource_changes_external_id_claim() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_resource_impl(
                &storage,
                make_resource_create("domain-1", "provider-1", "user-1", Some("ext-old")),
            )
            .await
            .unwrap();

        backend
            .update_resource_impl(
                &storage,
                "domain-1",
                "provider-1",
                ScimResourceType::User,
                "user-1",
                ScimResourceIndexUpdate {
                    external_id: Some(Some("ext-new".to_string())),
                    deprovisioned_at: None,
                },
            )
            .await
            .unwrap();

        // Old claim released: a new resource can now claim it.
        backend
            .create_resource_impl(
                &storage,
                make_resource_create("domain-1", "provider-1", "user-2", Some("ext-old")),
            )
            .await
            .unwrap();

        // New claim in effect: resolves back to user-1.
        let fetched = backend
            .get_resource_by_external_id_impl(
                &storage,
                "domain-1",
                "provider-1",
                ScimResourceType::User,
                "ext-new",
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.keystone_id, "user-1");
    }

    #[tokio::test]
    async fn test_update_resource_missing_errors() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let result = backend
            .update_resource_impl(
                &storage,
                "domain-1",
                "provider-1",
                ScimResourceType::User,
                "nonexistent",
                ScimResourceIndexUpdate {
                    external_id: None,
                    deprovisioned_at: Some(Some(1)),
                },
            )
            .await;
        assert!(result.is_err());
    }
}
