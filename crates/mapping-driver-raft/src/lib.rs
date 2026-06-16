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
//! # OpenStack Keystone Raft driver for the mapping provider
//!
//! Distributed storage backend for the mapping provider, persisting
//! `MappingRuleSet` rulesets and `VirtualUser` shadow registry records
//! across the Raft cluster via FjallDB.
//!
//! ## Architecture
//!
//! The driver implements the
//! [`MappingBackend`](openstack_keystone_core::mapping::backend::MappingBackend)
//! trait, delegating all mutations to the Raft consensus layer. Each operation
//! constructs a set of
//! [`Mutation`](openstack_keystone_distributed_storage::store_command::Mutation)
//! commands and executes them atomically within a single distributed
//! transaction.
//!
//! ## Keyspace Layout
//!
//! All keys are stored under the `mapping:` namespace. The two resource types
//! each have a primary key (direct ID lookup) and secondary index keys for
//! filtered listing:
//!
//! | Resource      | Key Pattern                                | Purpose                          |
//! |---------------|--------------------------------------------|----------------------------------|
//! | Ruleset (PK)  | `mapping:ruleset:id:<mapping_id>`          | Direct lookup by ruleset ID      |
//! | Ruleset (IX)  | `mapping:ruleset:domain:<domain_id>:<id>`  | Index for listing by domain      |
//! | VirtualUser   | `mapping:vuser:id:<user_id>`               | Direct lookup by virtual user ID |
//! | VirtualUser   | `mapping:vuser:domain:<domain_id>:<id>`    | Index for listing by domain      |
//! | VirtualUser   | `mapping:vuser:mapping:<mapping_id>:<id>`  | Index for listing by ruleset     |
//!
//! ## Storage Keyspace
//!
//! All mutations use the default keyspace (`None::<&str>`), which resolves to
//! `"data"`. Using a custom keyspace name inside a Raft transaction causes
//! FjallDB to fail with a storage error, as custom keyspaces cannot be created
//! atomically within a distributed transaction.
//!
//! ## Index Lifecycle
//!
//! Every create operation writes both the primary data entry and its secondary
//! index entries within a single transaction. Every delete operation first
//! reads the existing record to determine which index entries to clean up, then
//! removes them atomically alongside the primary entry. This guarantees index
//! consistency even under concurrent Raft proposals.

use std::collections::BTreeSet;

use async_trait::async_trait;

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::mapping::backend::MappingBackend;
use openstack_keystone_core::mapping::error::MappingProviderError;
use openstack_keystone_core_types::mapping::*;
use openstack_keystone_distributed_storage::{
    Metadata, StorageApi, StoreDataEnvelope, StoreError, store_command::Mutation,
};

/// Raft-backed storage driver for mapping rulesets and virtual user shadow
/// records.
///
/// Implements the
/// [`MappingBackend`](openstack_keystone_core::mapping::backend::MappingBackend)
/// trait. All storage operations are delegated to the FjallDB Raft layer via
/// [`StorageApi`](openstack_keystone_distributed_storage::StorageApi).
///
/// This struct is stateless; it is safe to share across threads and should be
/// instantiated as a singleton per service.
#[derive(Default)]
pub struct RaftBackend {}

// ---------------------------------------------------------------------------
// Key construction helpers
// ---------------------------------------------------------------------------

impl RaftBackend {
    // ----- Ruleset keys -----

    /// Get the primary storage key for a ruleset by its `mapping_id`.
    ///
    /// This is the canonical lookup key used for create, get, update, and
    /// delete operations on rulesets.
    ///
    /// # Parameters
    /// - `mapping_id`: The unique ruleset identifier.
    ///
    /// # Returns
    /// Key of the form `mapping:ruleset:id:<mapping_id>`.
    fn get_ruleset_id_key_name<I: AsRef<str>>(&self, mapping_id: I) -> String {
        format!("mapping:ruleset:id:{}", mapping_id.as_ref())
    }

    /// Get the prefix for scanning all ruleset entries.
    ///
    /// Used by [`list_rulesets_impl`](Self::list_rulesets_impl) as a fallback
    /// when no domain filter is specified.
    ///
    /// # Returns
    /// The constant prefix `mapping:ruleset:id:`.
    fn get_ruleset_prefix(&self) -> String {
        "mapping:ruleset:id:".to_string()
    }

    /// Get the secondary index key for a ruleset scoped by `domain_id`.
    ///
    /// This index enables efficient listing of rulesets within a tenant domain
    /// without scanning the entire keyspace.
    ///
    /// # Parameters
    /// - `mapping_id`: The ruleset identifier.
    /// - `domain_id`: The owning domain identifier.
    ///
    /// # Returns
    /// Key of the form `mapping:ruleset:domain:<domain_id>:<mapping_id>`.
    fn get_ruleset_domain_idx_key_name<I: AsRef<str>, D: AsRef<str>>(
        &self,
        mapping_id: I,
        domain_id: D,
    ) -> String {
        format!(
            "mapping:ruleset:domain:{}:{}",
            domain_id.as_ref(),
            mapping_id.as_ref()
        )
    }

    /// Get the prefix for scanning all rulesets within a domain.
    ///
    /// # Parameters
    /// - `domain_id`: The domain filter.
    ///
    /// # Returns
    /// Prefix of the form `mapping:ruleset:domain:<domain_id>:`.
    fn get_ruleset_by_domain_prefix<D: AsRef<str>>(&self, domain_id: D) -> String {
        format!("mapping:ruleset:domain:{}:", domain_id.as_ref())
    }

    /// Get the composite index key for a ruleset scoped by `(domain_id,
    /// source)`.
    ///
    /// This index enables efficient lookup of the single ruleset that matches
    /// a specific ingress provider within a tenant domain, used by
    /// `authenticate_by_mapping`.
    ///
    /// # Parameters
    /// - `mapping_id`: The ruleset identifier.
    /// - `domain_id`: The owning domain identifier.
    /// - `source_key`: The stable string representation of the identity source
    ///   (e.g., `"federation:okta-enterprise-idp"`).
    ///
    /// # Returns
    /// Key of the form
    /// `mapping:ruleset:source:<domain_id>:<source_key>:<mapping_id>`.
    fn get_ruleset_source_idx_key_name<I: AsRef<str>, D: AsRef<str>, S: AsRef<str>>(
        &self,
        mapping_id: I,
        domain_id: D,
        source_key: S,
    ) -> String {
        format!(
            "mapping:ruleset:source:{}:{}:{}",
            domain_id.as_ref(),
            source_key.as_ref(),
            mapping_id.as_ref()
        )
    }

    // ----- Virtual user keys -----

    /// Get the primary storage key for a virtual user shadow record by its
    /// `user_id`.
    ///
    /// This is the canonical lookup key used for all virtual user CRUD
    /// operations.
    ///
    /// # Parameters
    /// - `user_id`: The deterministic HMAC-SHA256-derived virtual user
    ///   identifier.
    ///
    /// # Returns
    /// Key of the form `mapping:vuser:id:<user_id>`.
    fn get_vuser_id_key_name<I: AsRef<str>>(&self, user_id: I) -> String {
        format!("mapping:vuser:id:{}", user_id.as_ref())
    }

    /// Get the prefix for scanning all virtual user entries.
    ///
    /// Used by [`list_virtual_users_impl`](Self::list_virtual_users_impl) as a
    /// fallback when no domain or mapping_id filter is specified.
    ///
    /// # Returns
    /// The constant prefix `mapping:vuser:id:`.
    fn get_vuser_prefix(&self) -> String {
        "mapping:vuser:id:".to_string()
    }

    /// Get the secondary index key for a virtual user scoped by `domain_id`.
    ///
    /// This index enables efficient listing of virtual users within a tenant
    /// domain.
    ///
    /// # Parameters
    /// - `user_id`: The virtual user identifier.
    /// - `domain_id`: The owning domain identifier.
    ///
    /// # Returns
    /// Key of the form `mapping:vuser:domain:<domain_id>:<user_id>`.
    fn get_vuser_domain_idx_key_name<I: AsRef<str>, D: AsRef<str>>(
        &self,
        user_id: I,
        domain_id: D,
    ) -> String {
        format!(
            "mapping:vuser:domain:{}:{}",
            domain_id.as_ref(),
            user_id.as_ref()
        )
    }

    /// Get the prefix for scanning all virtual users within a domain.
    ///
    /// # Parameters
    /// - `domain_id`: The domain filter.
    ///
    /// # Returns
    /// Prefix of the form `mapping:vuser:domain:<domain_id>:`.
    fn get_vuser_by_domain_prefix<D: AsRef<str>>(&self, domain_id: D) -> String {
        format!("mapping:vuser:domain:{}:", domain_id.as_ref())
    }

    /// Get the secondary index key for a virtual user scoped by `mapping_id`.
    ///
    /// This index enables efficient lookup of all virtual users that were
    /// issued tokens under a specific ruleset.
    ///
    /// # Parameters
    /// - `user_id`: The virtual user identifier.
    /// - `mapping_id`: The ruleset that authored the virtual user record.
    ///
    /// # Returns
    /// Key of the form `mapping:vuser:mapping:<mapping_id>:<user_id>`.
    fn get_vuser_mapping_idx_key_name<I: AsRef<str>, M: AsRef<str>>(
        &self,
        user_id: I,
        mapping_id: M,
    ) -> String {
        format!(
            "mapping:vuser:mapping:{}:{}",
            mapping_id.as_ref(),
            user_id.as_ref()
        )
    }

    /// Get the prefix for scanning all virtual users under a ruleset.
    ///
    /// # Parameters
    /// - `mapping_id`: The ruleset filter.
    ///
    /// # Returns
    /// Prefix of the form `mapping:vuser:mapping:<mapping_id>:`.
    fn get_vuser_by_mapping_prefix<M: AsRef<str>>(&self, mapping_id: M) -> String {
        format!("mapping:vuser:mapping:{}:", mapping_id.as_ref())
    }

    // ---------------------------------------------------------------------------
    // Storage-backed CRUD implementations (testable with MockStorage)
    // ---------------------------------------------------------------------------

    /// Atomically persist a new ruleset and its domain index entry.
    ///
    /// Executes a single distributed transaction containing:
    /// 1. `Mutation::set` for the primary data under `mapping:ruleset:id:`.
    /// 2. `Mutation::set_index` for the domain lookup index (only if
    ///    `domain_id` is present).
    ///
    /// # Parameters
    /// - `storage`: The storage API implementation.
    /// - `ruleset`: The fully-populated ruleset with `mapping_id` and
    ///   `ruleset_version` set.
    ///
    /// # Returns
    /// The persisted [`MappingRuleSet`].
    ///
    /// # Errors
    /// Returns [`StoreError`] if the distributed transaction fails.
    async fn create_ruleset_impl(
        &self,
        storage: &impl StorageApi,
        ruleset: MappingRuleSet,
    ) -> Result<MappingRuleSet, StoreError> {
        let obj = ruleset;
        let mut mutations = vec![Mutation::set(
            self.get_ruleset_id_key_name(&obj.mapping_id),
            obj.clone(),
            Metadata::new(),
            None::<&str>,
            None,
        )?];
        let idx_key = obj.domain_id.as_deref().unwrap_or("global");
        if let Some(ref did) = obj.domain_id {
            mutations.push(Mutation::set_index(
                self.get_ruleset_domain_idx_key_name(&obj.mapping_id, did),
            )?);
        }
        // Composite source index: domain + identity source
        mutations.push(Mutation::set_index(self.get_ruleset_source_idx_key_name(
            &obj.mapping_id,
            idx_key,
            obj.source.to_string_key(),
        ))?);
        storage.transaction(mutations).await?;
        Ok(obj)
    }

    /// Atomically persist a new virtual user shadow record and its index
    /// entries.
    ///
    /// Executes a single distributed transaction containing:
    /// 1. `Mutation::set` for the primary data under `mapping:vuser:id:`.
    /// 2. `Mutation::set_index` for the mapping_id index (always present).
    /// 3. `Mutation::set_index` for the domain lookup index (only if
    ///    `domain_id` is present).
    ///
    /// # Parameters
    /// - `storage`: The storage API implementation.
    /// - `metadata`: The fully-populated virtual user record.
    ///
    /// # Returns
    /// The persisted [`VirtualUser`].
    ///
    /// # Errors
    /// Returns [`StoreError`] if the distributed transaction fails.
    async fn create_virtual_user_impl(
        &self,
        storage: &impl StorageApi,
        metadata: VirtualUser,
    ) -> Result<VirtualUser, StoreError> {
        let mut mutations = vec![
            Mutation::set(
                self.get_vuser_id_key_name(&metadata.user_id),
                metadata.clone(),
                Metadata::new(),
                None::<&str>,
                None,
            )?,
            Mutation::set_index(
                self.get_vuser_mapping_idx_key_name(&metadata.user_id, &metadata.mapping_id),
            )?,
        ];
        if let Some(ref did) = metadata.domain_id {
            mutations.push(Mutation::set_index(
                self.get_vuser_domain_idx_key_name(&metadata.user_id, did),
            )?);
        }
        storage.transaction(mutations).await?;
        Ok(metadata)
    }

    /// Atomically remove a ruleset and its indexes.
    ///
    /// First reads the existing record to determine which indexes to clean up,
    /// then removes all entries atomically within a single transaction. If the
    /// ruleset does not already exist, this is a no-op.
    ///
    /// # Parameters
    /// - `storage`: The storage API implementation.
    /// - `mapping_id`: The ruleset identifier to delete.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the distributed transaction fails.
    async fn delete_ruleset_impl(
        &self,
        storage: &impl StorageApi,
        mapping_id: &str,
    ) -> Result<(), StoreError> {
        let curr: Option<StoreDataEnvelope<MappingRuleSet>> = storage
            .get_by_key(self.get_ruleset_id_key_name(mapping_id), None::<&str>)
            .await?;
        if let Some(env) = curr {
            let obj = &env.data;
            let rev = env.metadata.revision;
            let mut mutations = vec![Mutation::remove(
                self.get_ruleset_id_key_name(mapping_id),
                None::<&str>,
                Some(rev),
            )?];
            if let Some(ref did) = obj.domain_id {
                mutations.push(Mutation::remove_index(
                    self.get_ruleset_domain_idx_key_name(mapping_id, did),
                )?);
                mutations.push(Mutation::remove_index(
                    self.get_ruleset_source_idx_key_name(
                        mapping_id,
                        did,
                        obj.source.to_string_key(),
                    ),
                )?);
            }
            storage.transaction(mutations).await?;
        }
        Ok(())
    }

    /// Atomically remove a virtual user shadow record and its index entries.
    ///
    /// First reads the existing record to determine which indexes to clean up
    /// (both the mapping_id index and the domain index if present), then
    /// removes all entries atomically within a single transaction. If the
    /// record does not already exist, this is a no-op.
    ///
    /// # Parameters
    /// - `storage`: The storage API implementation.
    /// - `user_id`: The virtual user identifier to delete.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the distributed transaction fails.
    async fn delete_virtual_user_impl(
        &self,
        storage: &impl StorageApi,
        user_id: &str,
    ) -> Result<(), StoreError> {
        let curr: Option<StoreDataEnvelope<VirtualUser>> = storage
            .get_by_key(self.get_vuser_id_key_name(user_id), None::<&str>)
            .await?;
        if let Some(env) = curr {
            let obj = &env.data;
            let rev = env.metadata.revision;
            let mut mutations = vec![
                Mutation::remove(self.get_vuser_id_key_name(user_id), None::<&str>, Some(rev))?,
                Mutation::remove_index(
                    self.get_vuser_mapping_idx_key_name(user_id, &obj.mapping_id),
                )?,
            ];
            if let Some(ref did) = obj.domain_id {
                mutations.push(Mutation::remove_index(
                    self.get_vuser_domain_idx_key_name(user_id, did),
                )?);
            }
            storage.transaction(mutations).await?;
        }
        Ok(())
    }

    /// Fetch a ruleset by its `mapping_id`.
    ///
    /// # Parameters
    /// - `storage`: The storage API implementation.
    /// - `mapping_id`: The ruleset identifier.
    ///
    /// # Returns
    /// `Some(ruleset)` if found, `None` otherwise.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the read fails.
    async fn get_ruleset_impl(
        &self,
        storage: &impl StorageApi,
        mapping_id: &str,
    ) -> Result<Option<MappingRuleSet>, StoreError> {
        Ok(storage
            .get_by_key(self.get_ruleset_id_key_name(mapping_id), None::<&str>)
            .await?
            .map(|x| x.data))
    }

    /// Fetch a ruleset by its `(domain_id, source)` composite index.
    ///
    /// Used by `authenticate_by_mapping` to resolve the ruleset that matches
    /// a specific ingress provider within a tenant domain.
    ///
    /// # Parameters
    /// - `storage`: The storage API implementation.
    /// - `domain_id`: The owning domain identifier.
    /// - `source`: The identity source.
    ///
    /// # Returns
    /// `Some(ruleset)` if found, `None` otherwise.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the read fails.
    async fn get_ruleset_by_source_impl(
        &self,
        storage: &impl StorageApi,
        domain_id: &str,
        source: &IdentitySource,
    ) -> Result<Option<MappingRuleSet>, StoreError> {
        let source_key = source.to_string_key();
        // Index key: mapping:ruleset:source:<domain_id>:<source_key>:<mapping_id>
        let prefix = format!("mapping:ruleset:source:{}:{}:", domain_id, source_key);
        let indexes = storage.prefix_index(&prefix).await?;
        if indexes.is_empty() {
            return Ok(None);
        }
        // Extract mapping_id from the index key (after the last ':')
        let mapping_id = indexes[0]
            .split(':')
            .next_back()
            .map(|s| s.to_string())
            .ok_or_else(|| eyre::eyre!("malformed source index key: {}", indexes[0]))
            .map_err(StoreError::from)?;
        Ok(storage
            .get_by_key(self.get_ruleset_id_key_name(mapping_id), None::<&str>)
            .await?
            .map(|x| x.data))
    }

    /// Fetch a virtual user shadow record by its `user_id`.
    ///
    /// # Parameters
    /// - `storage`: The storage API implementation.
    /// - `user_id`: The virtual user identifier.
    ///
    /// # Returns
    /// `Some(user)` if found, `None` otherwise.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the read fails.
    async fn get_virtual_user_impl(
        &self,
        storage: &impl StorageApi,
        user_id: &str,
    ) -> Result<Option<VirtualUser>, StoreError> {
        Ok(storage
            .get_by_key(self.get_vuser_id_key_name(user_id), None::<&str>)
            .await?
            .map(|x| x.data))
    }

    /// List rulesets with optional filters.
    ///
    /// Supports filtering by `domain_id` and `enabled` status. When a
    /// `domain_id` filter is specified, the method uses the domain index
    /// key for efficient prefix scanning. When no domain filter is present,
    /// it falls back to scanning the full `mapping:ruleset:id:` prefix.
    ///
    /// Filtering is applied in two stages:
    /// 1. **Pre-filter** — domain index scan narrows candidate IDs (only when
    ///    `domain_id` is set).
    /// 2. **Post-filter** — remaining predicates (`enabled`) are evaluated
    ///    against hydrated objects.
    ///
    /// # Parameters
    /// - `storage`: The storage API implementation.
    /// - `params`: The list filter parameters.
    ///
    /// # Returns
    /// A vector of matching [`MappingRuleSet`] objects.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the scan fails.
    async fn list_rulesets_impl(
        &self,
        storage: &impl StorageApi,
        params: &MappingRuleSetListParameters,
    ) -> Result<Vec<MappingRuleSet>, StoreError> {
        let mut res: Vec<MappingRuleSet> = Vec::new();
        let mut post_filters: Vec<MappingRuleSetFilter> = Vec::new();
        if let Some(val) = &params.enabled {
            post_filters.push(MappingRuleSetFilter::Enabled(*val));
        }

        let mut pre_filter_ids: BTreeSet<String> = BTreeSet::new();
        if let Some(did) = &params.domain_id {
            post_filters.push(MappingRuleSetFilter::Domain(did.clone()));
            let prefix = self.get_ruleset_by_domain_prefix(did);
            let id_offset = if prefix.ends_with(':') {
                prefix.len()
            } else {
                prefix.len() + 1
            };
            pre_filter_ids.extend(
                storage
                    .prefix_index(self.get_ruleset_by_domain_prefix(did))
                    .await?
                    .into_iter()
                    .map(|entry| entry[id_offset..].into()),
            );
        }

        if !pre_filter_ids.is_empty() {
            for id in pre_filter_ids {
                if let Some(candidate) = storage
                    .get_by_key::<MappingRuleSet, String, &str>(
                        self.get_ruleset_id_key_name(id),
                        None::<&str>,
                    )
                    .await?
                    .map(|x| x.data)
                    && post_filters.iter().all(|f| f.matches(&candidate))
                {
                    res.push(candidate);
                }
            }
        } else {
            for candidate in storage
                .prefix::<MappingRuleSet, String, &str>(self.get_ruleset_prefix(), None::<&str>)
                .await?
                .into_iter()
                .map(|(_, v)| v.data)
            {
                if post_filters.iter().all(|f| f.matches(&candidate)) {
                    res.push(candidate);
                }
            }
        }
        Ok(res)
    }

    /// List virtual user shadow records with optional filters.
    ///
    /// Supports filtering by `domain_id`, `mapping_id`, and `enabled` status.
    /// When multiple indexable filters are present (`domain_id` and
    /// `mapping_id`), the method intersects both index result sets via
    /// [`BTreeSet::retain`] before hydrating candidate objects.
    ///
    /// Filtering is applied in two stages:
    /// 1. **Pre-filter** — domain and/or mapping_id index scan narrows
    ///    candidate IDs.
    /// 2. **Post-filter** — remaining predicates (`enabled`) are evaluated
    ///    against hydrated objects.
    ///
    /// # Parameters
    /// - `storage`: The storage API implementation.
    /// - `params`: The list filter parameters.
    ///
    /// # Returns
    /// A vector of matching [`VirtualUser`] objects.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the scan fails.
    async fn list_virtual_users_impl(
        &self,
        storage: &impl StorageApi,
        params: &VirtualUserListParameters,
    ) -> Result<Vec<VirtualUser>, StoreError> {
        let mut res: Vec<VirtualUser> = Vec::new();
        let mut post_filters: Vec<VirtualUserFilter> = Vec::new();
        if let Some(val) = &params.enabled {
            post_filters.push(VirtualUserFilter::Enabled(*val));
        }
        if let Some(val) = &params.mapping_id {
            post_filters.push(VirtualUserFilter::MappingId(val.clone()));
        }

        let mut pre_filter_ids: BTreeSet<String> = BTreeSet::new();
        if let Some(did) = &params.domain_id {
            post_filters.push(VirtualUserFilter::Domain(did.clone()));
            let prefix = self.get_vuser_by_domain_prefix(did);
            let id_offset = if prefix.ends_with(':') {
                prefix.len()
            } else {
                prefix.len() + 1
            };
            pre_filter_ids.extend(
                storage
                    .prefix_index(self.get_vuser_by_domain_prefix(did))
                    .await?
                    .into_iter()
                    .map(|entry| entry[id_offset..].into()),
            );
        }
        if let Some(mid) = &params.mapping_id {
            let prefix = self.get_vuser_by_mapping_prefix(mid);
            let id_offset = if prefix.ends_with(':') {
                prefix.len()
            } else {
                prefix.len() + 1
            };
            let by_mapping_ids: BTreeSet<String> = storage
                .prefix_index(self.get_vuser_by_mapping_prefix(mid))
                .await?
                .into_iter()
                .map(|entry| entry[id_offset..].into())
                .collect();
            if pre_filter_ids.is_empty() {
                pre_filter_ids = by_mapping_ids;
            } else {
                pre_filter_ids.retain(|x| by_mapping_ids.contains(x));
            }
        }

        if !pre_filter_ids.is_empty() {
            for id in pre_filter_ids {
                if let Some(candidate) = storage
                    .get_by_key::<VirtualUser, String, &str>(
                        self.get_vuser_id_key_name(id),
                        None::<&str>,
                    )
                    .await?
                    .map(|x| x.data)
                    && post_filters.iter().all(|f| f.matches(&candidate))
                {
                    res.push(candidate);
                }
            }
        } else {
            for candidate in storage
                .prefix::<VirtualUser, String, &str>(self.get_vuser_prefix(), None::<&str>)
                .await?
                .into_iter()
                .map(|(_, v)| v.data)
            {
                if post_filters.iter().all(|f| f.matches(&candidate)) {
                    res.push(candidate);
                }
            }
        }

        Ok(res)
    }

    /// Update an existing ruleset using optimistic concurrency control.
    ///
    /// Reads the current record, applies the partial update via
    /// [`MappingRuleSet::with_update`], then writes back with a revision
    /// bump. The `set_value` call includes the current revision as a CAS
    /// guard: if another Raft proposal modified the record concurrently,
    /// the write is rejected and the caller must retry.
    ///
    /// # Parameters
    /// - `storage`: The storage API implementation.
    /// - `mapping_id`: The ruleset identifier to update.
    /// - `data`: The partial update payload.
    ///
    /// # Returns
    /// The updated [`MappingRuleSet`].
    ///
    /// # Errors
    /// Returns [`StoreError`] if the record does not exist or the CAS check
    /// fails.
    async fn update_ruleset_impl(
        &self,
        storage: &impl StorageApi,
        mapping_id: &str,
        data: MappingRuleSetUpdate,
    ) -> Result<MappingRuleSet, StoreError> {
        let curr: StoreDataEnvelope<MappingRuleSet> = storage
            .get_by_key(self.get_ruleset_id_key_name(mapping_id), None::<&str>)
            .await?
            .ok_or(StoreError::Other(eyre::eyre!(
                "Mapping ruleset not found: {mapping_id}"
            )))?;
        let new = curr.data.with_update(data);
        let new_meta = curr.metadata.new_revision();
        storage
            .set_value(
                self.get_ruleset_id_key_name(mapping_id),
                StoreDataEnvelope {
                    data: new.clone(),
                    metadata: new_meta,
                },
                None::<&str>,
                Some(curr.metadata.revision),
            )
            .await?;
        Ok(new)
    }

    /// Update an existing virtual user shadow record using optimistic
    /// concurrency control.
    ///
    /// Reads the current record, replaces the data entirely, and bumps the
    /// revision. The `set_value` call includes the current revision as a
    /// CAS guard: if another Raft proposal modified the record
    /// concurrently, the write is rejected.
    ///
    /// # Parameters
    /// - `storage`: The storage API implementation.
    /// - `user_id`: The virtual user identifier to update.
    /// - `metadata`: The replacement virtual user record.
    ///
    /// # Returns
    /// The updated [`VirtualUser`].
    ///
    /// # Errors
    /// Returns [`StoreError`] if the record does not exist or the CAS check
    /// fails.
    async fn update_virtual_user_impl(
        &self,
        storage: &impl StorageApi,
        user_id: &str,
        metadata: VirtualUser,
    ) -> Result<VirtualUser, StoreError> {
        let curr: StoreDataEnvelope<VirtualUser> = storage
            .get_by_key(self.get_vuser_id_key_name(user_id), None::<&str>)
            .await?
            .ok_or(StoreError::Other(eyre::eyre!(
                "Virtual user not found: {user_id}"
            )))?;
        let new_meta = curr.metadata.new_revision();
        storage
            .set_value(
                self.get_vuser_id_key_name(user_id),
                StoreDataEnvelope {
                    data: metadata.clone(),
                    metadata: new_meta,
                },
                None::<&str>,
                Some(curr.metadata.revision),
            )
            .await?;
        Ok(metadata)
    }

    /// Disable a virtual user shadow record via CAS update.
    ///
    /// Reads the current record, sets `enabled: false`, and writes back with
    /// a revision bump. The current revision is used as a CAS guard.
    ///
    /// # Parameters
    /// - `storage`: The storage API implementation.
    /// - `user_id`: The virtual user identifier to disable.
    ///
    /// # Returns
    /// The disabled [`VirtualUser`].
    ///
    /// # Errors
    /// Returns [`StoreError`] if the record does not exist or the CAS check
    /// fails.
    async fn disable_virtual_user_impl(
        &self,
        storage: &impl StorageApi,
        user_id: &str,
    ) -> Result<VirtualUser, StoreError> {
        let curr: StoreDataEnvelope<VirtualUser> = storage
            .get_by_key(self.get_vuser_id_key_name(user_id), None::<&str>)
            .await?
            .ok_or(StoreError::Other(eyre::eyre!(
                "Virtual user not found: {user_id}"
            )))?;
        let new_meta = curr.metadata.new_revision();
        let mut data = curr.data;
        data.enabled = false;
        storage
            .set_value(
                self.get_vuser_id_key_name(user_id),
                StoreDataEnvelope {
                    data: data.clone(),
                    metadata: new_meta,
                },
                None::<&str>,
                Some(curr.metadata.revision),
            )
            .await?;
        Ok(data)
    }

    /// Enable (reactivate) a virtual user shadow record via CAS update.
    ///
    /// Reads the current record, sets `enabled: true`, and writes back with
    /// a revision bump. The current revision is used as a CAS guard.
    ///
    /// # Parameters
    /// - `storage`: The storage API implementation.
    /// - `user_id`: The virtual user identifier to enable.
    ///
    /// # Returns
    /// The enabled [`VirtualUser`].
    ///
    /// # Errors
    /// Returns [`StoreError`] if the record does not exist or the CAS check
    /// fails.
    async fn enable_virtual_user_impl(
        &self,
        storage: &impl StorageApi,
        user_id: &str,
    ) -> Result<VirtualUser, StoreError> {
        let curr: StoreDataEnvelope<VirtualUser> = storage
            .get_by_key(self.get_vuser_id_key_name(user_id), None::<&str>)
            .await?
            .ok_or(StoreError::Other(eyre::eyre!(
                "Virtual user not found: {user_id}"
            )))?;
        let new_meta = curr.metadata.new_revision();
        let mut data = curr.data;
        data.enabled = true;
        storage
            .set_value(
                self.get_vuser_id_key_name(user_id),
                StoreDataEnvelope {
                    data: data.clone(),
                    metadata: new_meta,
                },
                None::<&str>,
                Some(curr.metadata.revision),
            )
            .await?;
        Ok(data)
    }
}

// ---------------------------------------------------------------------------
// Post-filter enums
// ---------------------------------------------------------------------------

/// Post-filter predicates applied to ruleset candidates during
/// [`RaftBackend::list_rulesets_impl`].
///
/// These filters are evaluated against fully-hydrated [`MappingRuleSet`]
/// objects after the pre-filter stage has narrowed the candidate set via index
/// scan.
enum MappingRuleSetFilter {
    /// Match rulesets assigned to a specific domain ID.
    Domain(String),
    /// Match rulesets by their `enabled` flag.
    Enabled(bool),
}

impl MappingRuleSetFilter {
    /// Check if a ruleset matches this filter predicate.
    fn matches(&self, obj: &MappingRuleSet) -> bool {
        match self {
            Self::Domain(val) => obj.domain_id.as_ref().is_some_and(|d| d == val),
            Self::Enabled(val) => obj.enabled == *val,
        }
    }
}

/// Post-filter predicates applied to virtual user candidates during
/// [`RaftBackend::list_virtual_users_impl`].
///
/// These filters are evaluated against fully-hydrated [`VirtualUser`] objects
/// after the pre-filter stage has narrowed the candidate set via index scan.
enum VirtualUserFilter {
    /// Match virtual users created by a specific ruleset.
    MappingId(String),
    /// Match virtual users by their `enabled` flag.
    Enabled(bool),
    /// Match virtual users assigned to a specific domain ID.
    Domain(String),
}

impl VirtualUserFilter {
    /// Check if a virtual user matches this filter predicate.
    fn matches(&self, obj: &VirtualUser) -> bool {
        match self {
            Self::MappingId(val) => obj.mapping_id == *val,
            Self::Enabled(val) => obj.enabled == *val,
            Self::Domain(val) => obj.domain_id.as_ref().is_some_and(|d| d == val),
        }
    }
}

// ---------------------------------------------------------------------------
// MappingBackend trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl MappingBackend for RaftBackend {
    /// Create a new mapping ruleset.
    ///
    /// Persists the ruleset atomically via a distributed Raft transaction,
    /// creating both the primary data entry and the domain index entry.
    ///
    /// # Parameters
    /// - `state`: The service state containing the Raft storage handle.
    /// - `ruleset`: The fully-populated ruleset to persist.
    ///
    /// # Returns
    /// The created [`MappingRuleSet`].
    ///
    /// # Errors
    /// Returns [`MappingProviderError::RaftNotAvailable`] if the storage handle
    /// is missing, or [`MappingProviderError::RaftStoreError`] if the
    /// transaction fails.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_ruleset(
        &self,
        state: &ServiceState,
        ruleset: MappingRuleSet,
    ) -> Result<MappingRuleSet, MappingProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(MappingProviderError::RaftNotAvailable)?;
        self.create_ruleset_impl(raft, ruleset)
            .await
            .map_err(MappingProviderError::raft)
    }

    /// Create a new virtual user shadow record.
    ///
    /// Persists the record atomically via a distributed Raft transaction,
    /// creating the primary data entry and both the mapping_id and domain index
    /// entries.
    ///
    /// # Parameters
    /// - `state`: The service state containing the Raft storage handle.
    /// - `metadata`: The fully-populated virtual user record to persist.
    ///
    /// # Returns
    /// The created [`VirtualUser`].
    ///
    /// # Errors
    /// Returns [`MappingProviderError::RaftNotAvailable`] if the storage handle
    /// is missing, or [`MappingProviderError::RaftStoreError`] if the
    /// transaction fails.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_virtual_user(
        &self,
        state: &ServiceState,
        metadata: VirtualUser,
    ) -> Result<VirtualUser, MappingProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(MappingProviderError::RaftNotAvailable)?;
        self.create_virtual_user_impl(raft, metadata)
            .await
            .map_err(MappingProviderError::raft)
    }

    /// Delete a mapping ruleset.
    ///
    /// Reads the existing record to determine which index entries to clean up,
    /// then removes all entries atomically. If the ruleset does not exist, this
    /// is a no-op.
    ///
    /// # Parameters
    /// - `state`: The service state containing the Raft storage handle.
    /// - `mapping_id`: The ruleset identifier to delete.
    ///
    /// # Errors
    /// Returns [`MappingProviderError::RaftNotAvailable`] if the storage handle
    /// is missing, [`MappingProviderError::CasConflict`] on CAS conflict,
    /// or [`MappingProviderError::RaftStoreError`] if the transaction fails.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
    ) -> Result<(), MappingProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(MappingProviderError::RaftNotAvailable)?;
        match self.delete_ruleset_impl(raft, mapping_id).await {
            Ok(()) => Ok(()),
            Err(StoreError::Conflict {
                subject,
                description,
            }) => Err(MappingProviderError::CasConflict {
                subject,
                description,
            }),
            Err(e) => Err(MappingProviderError::raft(e)),
        }
    }

    /// Delete a virtual user shadow record.
    ///
    /// Reads the existing record to determine which index entries to clean up
    /// (mapping_id index and domain index), then removes all entries
    /// atomically. If the record does not exist, this is a no-op.
    ///
    /// # Parameters
    /// - `state`: The service state containing the Raft storage handle.
    /// - `user_id`: The virtual user identifier to delete.
    ///
    /// # Errors
    /// Returns [`MappingProviderError::RaftNotAvailable`] if the storage handle
    /// is missing, [`MappingProviderError::CasConflict`] on CAS conflict,
    /// or [`MappingProviderError::RaftStoreError`] if the transaction fails.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), MappingProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(MappingProviderError::RaftNotAvailable)?;
        match self.delete_virtual_user_impl(raft, user_id).await {
            Ok(()) => Ok(()),
            Err(StoreError::Conflict {
                subject,
                description,
            }) => Err(MappingProviderError::CasConflict {
                subject,
                description,
            }),
            Err(e) => Err(MappingProviderError::raft(e)),
        }
    }

    /// Fetch a mapping ruleset by ID.
    ///
    /// # Parameters
    /// - `state`: The service state containing the Raft storage handle.
    /// - `mapping_id`: The ruleset identifier.
    ///
    /// # Returns
    /// `Some(ruleset)` if found, `None` otherwise.
    ///
    /// # Errors
    /// Returns [`MappingProviderError::RaftNotAvailable`] if the storage handle
    /// is missing, or [`MappingProviderError::RaftStoreError`] if the read
    /// fails.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
    ) -> Result<Option<MappingRuleSet>, MappingProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(MappingProviderError::RaftNotAvailable)?;
        self.get_ruleset_impl(raft, mapping_id)
            .await
            .map_err(MappingProviderError::raft)
    }

    /// Fetch a ruleset by its `(domain_id, source)` composite index.
    ///
    /// # Parameters
    /// - `state`: The service state containing the Raft storage handle.
    /// - `domain_id`: The owning domain identifier.
    /// - `source`: The identity source.
    ///
    /// # Returns
    /// `Some(ruleset)` if found, `None` otherwise.
    ///
    /// # Errors
    /// Returns [`MappingProviderError::RaftNotAvailable`] if the storage handle
    /// is missing, or [`MappingProviderError::RaftStoreError`] if the read
    /// fails.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_ruleset_by_source<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        source: &'a IdentitySource,
    ) -> Result<Option<MappingRuleSet>, MappingProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(MappingProviderError::RaftNotAvailable)?;
        self.get_ruleset_by_source_impl(raft, domain_id, source)
            .await
            .map_err(MappingProviderError::raft)
    }

    /// Fetch a virtual user shadow record by user ID.
    ///
    /// # Parameters
    /// - `state`: The service state containing the Raft storage handle.
    /// - `user_id`: The virtual user identifier.
    ///
    /// # Returns
    /// `Some(user)` if found, `None` otherwise.
    ///
    /// # Errors
    /// Returns [`MappingProviderError::RaftNotAvailable`] if the storage handle
    /// is missing, or [`MappingProviderError::RaftStoreError`] if the read
    /// fails.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<VirtualUser>, MappingProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(MappingProviderError::RaftNotAvailable)?;
        self.get_virtual_user_impl(raft, user_id)
            .await
            .map_err(MappingProviderError::raft)
    }

    /// List mapping rulesets with optional filters.
    ///
    /// Supports filtering by `domain_id` and `enabled` status. When a
    /// `domain_id` filter is specified, uses the domain index for efficient
    /// prefix scanning.
    ///
    /// # Parameters
    /// - `state`: The service state containing the Raft storage handle.
    /// - `params`: The list filter parameters.
    ///
    /// # Returns
    /// A vector of matching [`MappingRuleSet`] objects.
    ///
    /// # Errors
    /// Returns [`MappingProviderError::RaftNotAvailable`] if the storage handle
    /// is missing, or [`MappingProviderError::RaftStoreError`] if the scan
    /// fails.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_rulesets(
        &self,
        state: &ServiceState,
        params: &MappingRuleSetListParameters,
    ) -> Result<Vec<MappingRuleSet>, MappingProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(MappingProviderError::RaftNotAvailable)?;
        self.list_rulesets_impl(raft, params)
            .await
            .map_err(MappingProviderError::raft)
    }

    /// List virtual user shadow records with optional filters.
    ///
    /// Supports filtering by `domain_id`, `mapping_id`, and `enabled` status.
    /// When multiple indexable filters are present, intersects both index
    /// result sets.
    ///
    /// # Parameters
    /// - `state`: The service state containing the Raft storage handle.
    /// - `params`: The list filter parameters.
    ///
    /// # Returns
    /// A vector of matching [`VirtualUser`] objects.
    ///
    /// # Errors
    /// Returns [`MappingProviderError::RaftNotAvailable`] if the storage handle
    /// is missing, or [`MappingProviderError::RaftStoreError`] if the scan
    /// fails.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_virtual_users(
        &self,
        state: &ServiceState,
        params: &VirtualUserListParameters,
    ) -> Result<Vec<VirtualUser>, MappingProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(MappingProviderError::RaftNotAvailable)?;
        self.list_virtual_users_impl(raft, params)
            .await
            .map_err(MappingProviderError::raft)
    }

    /// Update an existing mapping ruleset using optimistic concurrency control.
    ///
    /// Reads the current record, applies the partial update via
    /// [`MappingRuleSet::with_update`], then writes back with a revision
    /// bump. The current revision is passed as a CAS guard: if another Raft
    /// proposal modified the record concurrently, the write is rejected.
    ///
    /// # Parameters
    /// - `state`: The service state containing the Raft storage handle.
    /// - `mapping_id`: The ruleset identifier to update.
    /// - `data`: The partial update payload.
    ///
    /// # Returns
    /// The updated [`MappingRuleSet`].
    ///
    /// # Errors
    /// Returns [`MappingProviderError::NotFound`] if the ruleset does not
    /// exist, [`MappingProviderError::RaftNotAvailable`] if the storage
    /// handle is missing, or [`MappingProviderError::RaftStoreError`] if
    /// the CAS check fails.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
        data: MappingRuleSetUpdate,
    ) -> Result<MappingRuleSet, MappingProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(MappingProviderError::RaftNotAvailable)?;
        match self.update_ruleset_impl(raft, mapping_id, data).await {
            Ok(r) => Ok(r),
            Err(e) => {
                if e.to_string().contains("not found") {
                    Err(MappingProviderError::NotFound(mapping_id.to_string()))
                } else {
                    Err(MappingProviderError::raft(e))
                }
            }
        }
    }

    /// Update an existing virtual user shadow record using optimistic
    /// concurrency control.
    ///
    /// Reads the current record, replaces the data entirely, and bumps the
    /// revision. The current revision is passed as a CAS guard: if another
    /// Raft proposal modified the record concurrently, the write is
    /// rejected.
    ///
    /// # Parameters
    /// - `state`: The service state containing the Raft storage handle.
    /// - `user_id`: The virtual user identifier to update.
    /// - `metadata`: The replacement virtual user record.
    ///
    /// # Returns
    /// The updated [`VirtualUser`].
    ///
    /// # Errors
    /// Returns [`MappingProviderError::NotFound`] if the record does not exist,
    /// [`MappingProviderError::RaftNotAvailable`] if the storage handle is
    /// missing, or [`MappingProviderError::RaftStoreError`] if the CAS
    /// check fails.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        metadata: VirtualUser,
    ) -> Result<VirtualUser, MappingProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(MappingProviderError::RaftNotAvailable)?;
        match self.update_virtual_user_impl(raft, user_id, metadata).await {
            Ok(r) => Ok(r),
            Err(e) => {
                if e.to_string().contains("not found") {
                    Err(MappingProviderError::NotFound(user_id.to_string()))
                } else {
                    Err(MappingProviderError::raft(e))
                }
            }
        }
    }

    /// Disable a virtual user shadow record.
    ///
    /// Reads the current record, sets `enabled` to `false`, and writes back
    /// with a revision bump using optimistic concurrency control.
    ///
    /// # Parameters
    /// - `state`: The service state containing the Raft storage handle.
    /// - `user_id`: The virtual user identifier to disable.
    ///
    /// # Returns
    /// The disabled [`VirtualUser`].
    ///
    /// # Errors
    /// Returns [`MappingProviderError::NotFound`] if the record does not exist,
    /// [`MappingProviderError::RaftNotAvailable`] if the storage handle is
    /// missing, or [`MappingProviderError::RaftStoreError`] if the CAS
    /// check fails.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn disable_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<VirtualUser, MappingProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(MappingProviderError::RaftNotAvailable)?;
        match self.disable_virtual_user_impl(raft, user_id).await {
            Ok(r) => Ok(r),
            Err(e) => {
                if e.to_string().contains("not found") {
                    Err(MappingProviderError::NotFound(user_id.to_string()))
                } else {
                    Err(MappingProviderError::raft(e))
                }
            }
        }
    }

    /// Enable (reactivate) a virtual user shadow record.
    ///
    /// Reads the current record, sets `enabled` to `true`, and writes back
    /// with a revision bump using optimistic concurrency control.
    ///
    /// # Parameters
    /// - `state`: The service state containing the Raft storage handle.
    /// - `user_id`: The virtual user identifier to enable.
    ///
    /// # Returns
    /// The enabled [`VirtualUser`].
    ///
    /// # Errors
    /// Returns [`MappingProviderError::NotFound`] if the record does not exist,
    /// [`MappingProviderError::RaftNotAvailable`] if the storage handle is
    /// missing, or [`MappingProviderError::RaftStoreError`] if the CAS
    /// check fails.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn enable_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<VirtualUser, MappingProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(MappingProviderError::RaftNotAvailable)?;
        match self.enable_virtual_user_impl(raft, user_id).await {
            Ok(r) => Ok(r),
            Err(e) => {
                if e.to_string().contains("not found") {
                    Err(MappingProviderError::NotFound(user_id.to_string()))
                } else {
                    Err(MappingProviderError::raft(e))
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
    use openstack_keystone_core_types::mapping::{DomainResolutionMode, IdentitySource};
    use openstack_keystone_core_types::role::RoleRef;
    use openstack_keystone_distributed_storage::mock::MockStorage;

    // ---------------------------------------------------------------------------
    // Factory helpers for test data
    // ---------------------------------------------------------------------------

    fn make_ruleset(mapping_id: &str, domain_id: Option<&str>, enabled: bool) -> MappingRuleSet {
        MappingRuleSet {
            mapping_id: mapping_id.to_string(),
            domain_id: domain_id.map(|d| d.to_string()),
            source: IdentitySource::Federation {
                idp_id: "idp-1".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled,
            rules: vec![],
            ruleset_version: 0,
        }
    }

    fn make_virtual_user(
        user_id: &str,
        mapping_id: &str,
        domain_id: Option<&str>,
        enabled: bool,
    ) -> VirtualUser {
        VirtualUser {
            user_id: user_id.to_string(),
            unique_workload_id: format!("wl-{user_id}"),
            mapping_id: mapping_id.to_string(),
            matched_rule_name: "rule-1".to_string(),
            domain_id: domain_id.map(|d| d.to_string()),
            resolved_user_name: format!("user-{user_id}"),
            is_system: false,
            resolved_group_bindings: vec![],
            authorizations: vec![Authorization::Domain {
                domain_id: "domain-default".to_string(),
                roles: vec![RoleRef {
                    domain_id: None,
                    id: "admin".to_string(),
                    name: Some("Admin".to_string()),
                }],
            }],
            ruleset_version: 0,
            enabled,
            created_at: 1_000_000_000,
            last_authenticated_at: 1_000_000_000,
        }
    }

    // ---------------------------------------------------------------------------
    // Key construction helpers tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_ruleset_id_key_name() {
        let backend = RaftBackend::default();
        let key = backend.get_ruleset_id_key_name("my-ruleset-id");
        assert_eq!(key, "mapping:ruleset:id:my-ruleset-id");
    }

    #[test]
    fn test_ruleset_prefix() {
        let backend = RaftBackend::default();
        assert_eq!(backend.get_ruleset_prefix(), "mapping:ruleset:id:");
    }

    #[test]
    fn test_ruleset_domain_idx_key_name() {
        let backend = RaftBackend::default();
        let key = backend.get_ruleset_domain_idx_key_name("rs-1", "domain-a");
        assert_eq!(key, "mapping:ruleset:domain:domain-a:rs-1");
    }

    #[test]
    fn test_ruleset_domain_prefix() {
        let backend = RaftBackend::default();
        let key = backend.get_ruleset_by_domain_prefix("domain-b");
        assert_eq!(key, "mapping:ruleset:domain:domain-b:");
    }

    #[test]
    fn test_vuser_id_key_name() {
        let backend = RaftBackend::default();
        let key = backend.get_vuser_id_key_name("vuser-123");
        assert_eq!(key, "mapping:vuser:id:vuser-123");
    }

    #[test]
    fn test_vuser_prefix() {
        let backend = RaftBackend::default();
        assert_eq!(backend.get_vuser_prefix(), "mapping:vuser:id:");
    }

    #[test]
    fn test_vuser_domain_idx_key_name() {
        let backend = RaftBackend::default();
        let key = backend.get_vuser_domain_idx_key_name("vuser-1", "domain-x");
        assert_eq!(key, "mapping:vuser:domain:domain-x:vuser-1");
    }

    #[test]
    fn test_vuser_domain_prefix() {
        let backend = RaftBackend::default();
        let key = backend.get_vuser_by_domain_prefix("my-domain");
        assert_eq!(key, "mapping:vuser:domain:my-domain:");
    }

    #[test]
    fn test_vuser_mapping_idx_key_name() {
        let backend = RaftBackend::default();
        let key = backend.get_vuser_mapping_idx_key_name("vuser-99", "mapping-42");
        assert_eq!(key, "mapping:vuser:mapping:mapping-42:vuser-99");
    }

    #[test]
    fn test_vuser_mapping_prefix() {
        let backend = RaftBackend::default();
        let key = backend.get_vuser_by_mapping_prefix("my-mapping");
        assert_eq!(key, "mapping:vuser:mapping:my-mapping:");
    }

    // ---------------------------------------------------------------------------
    // Key uniqueness tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_ruleset_keys_are_unique() {
        let backend = RaftBackend::default();
        let id_key = backend.get_ruleset_id_key_name("rs-1");
        let domain_key = backend.get_ruleset_domain_idx_key_name("rs-1", "domain-a");
        assert_ne!(id_key, domain_key);
    }

    #[test]
    fn test_vuser_keys_are_unique() {
        let backend = RaftBackend::default();
        let id_key = backend.get_vuser_id_key_name("vu-1");
        let domain_key = backend.get_vuser_domain_idx_key_name("vu-1", "domain-a");
        let mapping_key = backend.get_vuser_mapping_idx_key_name("vu-1", "mapping-1");
        assert_ne!(id_key, domain_key);
        assert_ne!(id_key, mapping_key);
        assert_ne!(domain_key, mapping_key);
    }

    #[test]
    fn test_ruleset_and_vuser_keys_are_separate() {
        let backend = RaftBackend::default();
        let rs_key = backend.get_ruleset_id_key_name("same-id");
        let vu_key = backend.get_vuser_id_key_name("same-id");
        assert_ne!(rs_key, vu_key);
    }

    #[test]
    fn test_ruleset_domain_prefix_id_extraction() {
        let backend = RaftBackend::default();
        let prefix = backend.get_ruleset_by_domain_prefix("domain-a");
        let id_offset = if prefix.ends_with(':') {
            prefix.len()
        } else {
            prefix.len() + 1
        };
        let full_key = "mapping:ruleset:domain:domain-a:rs-5";
        assert_eq!(&full_key[id_offset..], "rs-5");
    }

    #[test]
    fn test_vuser_domain_prefix_id_extraction() {
        let backend = RaftBackend::default();
        let prefix = backend.get_vuser_by_domain_prefix("d1");
        let id_offset = if prefix.ends_with(':') {
            prefix.len()
        } else {
            prefix.len() + 1
        };
        let full_key = "mapping:vuser:domain:d1:vu-7";
        assert_eq!(&full_key[id_offset..], "vu-7");
    }

    #[test]
    fn test_vuser_mapping_prefix_id_extraction() {
        let backend = RaftBackend::default();
        let prefix = backend.get_vuser_by_mapping_prefix("m1");
        let id_offset = if prefix.ends_with(':') {
            prefix.len()
        } else {
            prefix.len() + 1
        };
        let full_key = "mapping:vuser:mapping:m1:vu-3";
        assert_eq!(&full_key[id_offset..], "vu-3");
    }

    // ---------------------------------------------------------------------------
    // MockStorage integration tests: ruleset CRUD
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_create_ruleset() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let ruleset = make_ruleset("rs-1", Some("domain-1"), true);
        let result = backend.create_ruleset_impl(&storage, ruleset.clone()).await;
        assert!(result.is_ok());
        let created = result.unwrap();
        assert_eq!(created.mapping_id, "rs-1");
        assert_eq!(created.domain_id.as_deref(), Some("domain-1"));
    }

    #[tokio::test]
    async fn test_create_ruleset_without_domain() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let ruleset = make_ruleset("rs-2", None, false);
        let result = backend.create_ruleset_impl(&storage, ruleset.clone()).await;
        assert!(result.is_ok());
        let created = result.unwrap();
        assert_eq!(created.mapping_id, "rs-2");
        assert!(created.domain_id.is_none());
    }

    #[tokio::test]
    async fn test_get_ruleset_exists() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let ruleset = make_ruleset("rs-3", Some("domain-a"), true);
        backend
            .create_ruleset_impl(&storage, ruleset)
            .await
            .unwrap();
        let result = backend.get_ruleset_impl(&storage, "rs-3").await;
        assert!(result.is_ok());
        let found = result.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().mapping_id, "rs-3");
    }

    #[tokio::test]
    async fn test_get_ruleset_not_found() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let result = backend.get_ruleset_impl(&storage, "nonexistent").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_ruleset() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let ruleset = make_ruleset("rs-4", Some("domain-1"), true);
        backend
            .create_ruleset_impl(&storage, ruleset)
            .await
            .unwrap();
        backend.delete_ruleset_impl(&storage, "rs-4").await.unwrap();
        let found = backend.get_ruleset_impl(&storage, "rs-4").await;
        assert!(found.is_ok());
        assert!(found.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_ruleset_not_found() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let result = backend.delete_ruleset_impl(&storage, "nonexistent").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_update_ruleset() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let ruleset = make_ruleset("rs-5", Some("domain-1"), true);
        backend
            .create_ruleset_impl(&storage, ruleset)
            .await
            .unwrap();
        let update = MappingRuleSetUpdate {
            enabled: Some(false),
            allowed_domains: None,
            rules: None,
        };
        let result = backend.update_ruleset_impl(&storage, "rs-5", update).await;
        assert!(result.is_ok());
        let updated = result.unwrap();
        assert!(!updated.enabled);
    }

    #[tokio::test]
    async fn test_update_ruleset_not_found() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let update = MappingRuleSetUpdate::default();
        let result = backend
            .update_ruleset_impl(&storage, "nonexistent", update)
            .await;
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------------------
    // MockStorage integration tests: list rulesets
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_list_rulesets_all() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        backend
            .create_ruleset_impl(&storage, make_ruleset("rs-a", Some("domain-1"), true))
            .await
            .unwrap();
        backend
            .create_ruleset_impl(&storage, make_ruleset("rs-b", Some("domain-2"), true))
            .await
            .unwrap();
        backend
            .create_ruleset_impl(&storage, make_ruleset("rs-c", Some("domain-1"), false))
            .await
            .unwrap();
        let params = MappingRuleSetListParameters::default();
        let result = backend.list_rulesets_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_list_rulesets_by_domain() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        backend
            .create_ruleset_impl(&storage, make_ruleset("rs-a", Some("domain-1"), true))
            .await
            .unwrap();
        backend
            .create_ruleset_impl(&storage, make_ruleset("rs-b", Some("domain-2"), true))
            .await
            .unwrap();
        backend
            .create_ruleset_impl(&storage, make_ruleset("rs-c", Some("domain-1"), false))
            .await
            .unwrap();
        let params = MappingRuleSetListParameters {
            domain_id: Some("domain-1".to_string()),
            ..MappingRuleSetListParameters::default()
        };
        let result = backend.list_rulesets_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_list_rulesets_by_enabled() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        backend
            .create_ruleset_impl(&storage, make_ruleset("rs-a", Some("domain-1"), true))
            .await
            .unwrap();
        backend
            .create_ruleset_impl(&storage, make_ruleset("rs-b", Some("domain-2"), true))
            .await
            .unwrap();
        backend
            .create_ruleset_impl(&storage, make_ruleset("rs-c", Some("domain-1"), false))
            .await
            .unwrap();
        let params = MappingRuleSetListParameters {
            enabled: Some(true),
            ..MappingRuleSetListParameters::default()
        };
        let result = backend.list_rulesets_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_list_rulesets_empty() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let params = MappingRuleSetListParameters::default();
        let result = backend.list_rulesets_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    // ---------------------------------------------------------------------------
    // MockStorage integration tests: virtual user CRUD
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_create_virtual_user() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let vu = make_virtual_user("vu-1", "rs-1", Some("domain-1"), true);
        let result = backend.create_virtual_user_impl(&storage, vu.clone()).await;
        assert!(result.is_ok());
        let created = result.unwrap();
        assert_eq!(created.user_id, "vu-1");
        assert_eq!(created.mapping_id, "rs-1");
    }

    #[tokio::test]
    async fn test_get_virtual_user_exists() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let vu = make_virtual_user("vu-2", "rs-1", Some("domain-1"), true);
        backend
            .create_virtual_user_impl(&storage, vu)
            .await
            .unwrap();
        let result = backend.get_virtual_user_impl(&storage, "vu-2").await;
        assert!(result.is_ok());
        let found = result.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().user_id, "vu-2");
    }

    #[tokio::test]
    async fn test_get_virtual_user_not_found() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let result = backend.get_virtual_user_impl(&storage, "nonexistent").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_virtual_user() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let vu = make_virtual_user("vu-3", "rs-1", Some("domain-1"), true);
        backend
            .create_virtual_user_impl(&storage, vu)
            .await
            .unwrap();
        backend
            .delete_virtual_user_impl(&storage, "vu-3")
            .await
            .unwrap();
        let found = backend.get_virtual_user_impl(&storage, "vu-3").await;
        assert!(found.is_ok());
        assert!(found.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_virtual_user_not_found() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let result = backend
            .delete_virtual_user_impl(&storage, "nonexistent")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_update_virtual_user() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let mut vu = make_virtual_user("vu-4", "rs-1", Some("domain-1"), true);
        backend
            .create_virtual_user_impl(&storage, vu.clone())
            .await
            .unwrap();
        vu.enabled = false;
        let result = backend.update_virtual_user_impl(&storage, "vu-4", vu).await;
        assert!(result.is_ok());
        let updated = result.unwrap();
        assert!(!updated.enabled);
    }

    #[tokio::test]
    async fn test_update_virtual_user_not_found() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let vu = make_virtual_user("vu-x", "rs-x", None, false);
        let result = backend
            .update_virtual_user_impl(&storage, "nonexistent", vu)
            .await;
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------------------
    // MockStorage integration tests: list virtual users
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_list_virtual_users_all() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-a", "rs-1", Some("domain-1"), true),
            )
            .await
            .unwrap();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-b", "rs-2", Some("domain-2"), true),
            )
            .await
            .unwrap();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-c", "rs-1", Some("domain-1"), false),
            )
            .await
            .unwrap();
        let params = VirtualUserListParameters::default();
        let result = backend.list_virtual_users_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_list_virtual_users_by_domain() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-a", "rs-1", Some("domain-1"), true),
            )
            .await
            .unwrap();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-b", "rs-2", Some("domain-2"), true),
            )
            .await
            .unwrap();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-c", "rs-1", Some("domain-1"), false),
            )
            .await
            .unwrap();
        let params = VirtualUserListParameters {
            domain_id: Some("domain-1".to_string()),
            ..VirtualUserListParameters::default()
        };
        let result = backend.list_virtual_users_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_list_virtual_users_by_mapping_id() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-a", "rs-1", Some("domain-1"), true),
            )
            .await
            .unwrap();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-b", "rs-2", Some("domain-2"), true),
            )
            .await
            .unwrap();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-c", "rs-1", Some("domain-1"), false),
            )
            .await
            .unwrap();
        let params = VirtualUserListParameters {
            mapping_id: Some("rs-1".to_string()),
            ..VirtualUserListParameters::default()
        };
        let result = backend.list_virtual_users_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_list_virtual_users_by_domain_and_mapping_id() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-a", "rs-1", Some("domain-1"), true),
            )
            .await
            .unwrap();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-b", "rs-1", Some("domain-2"), true),
            )
            .await
            .unwrap();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-c", "rs-2", Some("domain-1"), false),
            )
            .await
            .unwrap();
        let params = VirtualUserListParameters {
            domain_id: Some("domain-1".to_string()),
            mapping_id: Some("rs-1".to_string()),
            ..VirtualUserListParameters::default()
        };
        let result = backend.list_virtual_users_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_list_virtual_users_empty() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let params = VirtualUserListParameters::default();
        let result = backend.list_virtual_users_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    // ---------------------------------------------------------------------------
    // Index lifecycle tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_ruleset_index_created_and_cleaned() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let ruleset = make_ruleset("rs-idx", Some("domain-idx"), true);
        backend
            .create_ruleset_impl(&storage, ruleset)
            .await
            .unwrap();
        let idx = storage
            .prefix_index("mapping:ruleset:domain:domain-idx:")
            .await
            .unwrap();
        assert_eq!(idx.len(), 1);
        backend
            .delete_ruleset_impl(&storage, "rs-idx")
            .await
            .unwrap();
        let idx = storage
            .prefix_index("mapping:ruleset:domain:domain-idx:")
            .await
            .unwrap();
        assert_eq!(idx.len(), 0);
    }

    #[tokio::test]
    async fn test_virtual_user_indexes_created_and_cleaned() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let vu = make_virtual_user("vu-idx", "rs-idx", Some("domain-idx"), true);
        backend
            .create_virtual_user_impl(&storage, vu)
            .await
            .unwrap();
        let domain_idx = storage
            .prefix_index("mapping:vuser:domain:domain-idx:")
            .await
            .unwrap();
        assert_eq!(domain_idx.len(), 1);
        let mapping_idx = storage
            .prefix_index("mapping:vuser:mapping:rs-idx:")
            .await
            .unwrap();
        assert_eq!(mapping_idx.len(), 1);
        backend
            .delete_virtual_user_impl(&storage, "vu-idx")
            .await
            .unwrap();
        let domain_idx = storage
            .prefix_index("mapping:vuser:domain:domain-idx:")
            .await
            .unwrap();
        assert_eq!(domain_idx.len(), 0);
        let mapping_idx = storage
            .prefix_index("mapping:vuser:mapping:rs-idx:")
            .await
            .unwrap();
        assert_eq!(mapping_idx.len(), 0);
    }

    // ---------------------------------------------------------------------------
    // get_ruleset_by_source tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_get_ruleset_by_source_found() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let ruleset = make_ruleset("rs-src-1", Some("domain-src"), true);
        backend
            .create_ruleset_impl(&storage, ruleset.clone())
            .await
            .unwrap();
        let source = IdentitySource::Federation {
            idp_id: "idp-1".to_string(),
        };
        let result = backend
            .get_ruleset_by_source_impl(&storage, "domain-src", &source)
            .await;
        assert!(result.is_ok());
        let found = result.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().mapping_id, "rs-src-1");
    }

    #[tokio::test]
    async fn test_get_ruleset_by_source_not_found() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let ruleset = make_ruleset("rs-src-2", Some("domain-src"), true);
        backend
            .create_ruleset_impl(&storage, ruleset)
            .await
            .unwrap();
        let source = IdentitySource::Federation {
            idp_id: "idp-nonexistent".to_string(),
        };
        let result = backend
            .get_ruleset_by_source_impl(&storage, "domain-src", &source)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // ---------------------------------------------------------------------------
    // disable/enable virtual user tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_disable_virtual_user_impl() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let vu = make_virtual_user("vu-disable", "rs-1", Some("domain-1"), true);
        backend
            .create_virtual_user_impl(&storage, vu)
            .await
            .unwrap();
        let result = backend
            .disable_virtual_user_impl(&storage, "vu-disable")
            .await;
        assert!(result.is_ok());
        let disabled = result.unwrap();
        assert!(!disabled.enabled);
    }

    #[tokio::test]
    async fn test_enable_virtual_user_impl() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let vu = make_virtual_user("vu-enable", "rs-1", Some("domain-1"), false);
        backend
            .create_virtual_user_impl(&storage, vu)
            .await
            .unwrap();
        let result = backend
            .enable_virtual_user_impl(&storage, "vu-enable")
            .await;
        assert!(result.is_ok());
        let enabled = result.unwrap();
        assert!(enabled.enabled);
    }

    // ---------------------------------------------------------------------------
    // list virtual users by enabled filter
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_list_virtual_users_by_enabled() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-en-1", "rs-1", Some("domain-1"), true),
            )
            .await
            .unwrap();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-en-2", "rs-2", Some("domain-2"), true),
            )
            .await
            .unwrap();
        backend
            .create_virtual_user_impl(
                &storage,
                make_virtual_user("vu-en-3", "rs-1", Some("domain-1"), false),
            )
            .await
            .unwrap();
        let params = VirtualUserListParameters {
            enabled: Some(true),
            ..VirtualUserListParameters::default()
        };
        let result = backend.list_virtual_users_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    // ---------------------------------------------------------------------------
    // create virtual user without domain
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_create_virtual_user_without_domain() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();
        let vu = make_virtual_user("vu-no-domain", "rs-11", None, true);
        let result = backend.create_virtual_user_impl(&storage, vu.clone()).await;
        assert!(result.is_ok());
        let created = result.unwrap();
        assert_eq!(created.user_id, "vu-no-domain");
        assert!(created.domain_id.is_none());
        let domain_idx = storage.prefix_index("mapping:vuser:domain:").await.unwrap();
        assert!(
            !domain_idx
                .iter()
                .any(|k: &String| k.contains("vu-no-domain"))
        );
    }
}
