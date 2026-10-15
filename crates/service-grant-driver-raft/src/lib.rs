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
//! # Raft driver for service grants (ADR 0036 §4)
//!
//! Primary records live in the `data` keyspace under
//! `service_grant:v1:<domain_id>:<id>`. Payload-free index keys (index
//! keyspace) resolve a grant by id, grantor, grantee and project:
//!
//! - `service_grant:id_idx:v1:<id>:<domain_id>`
//! - `service_grant:grantor_idx:v1:<user_id>:<domain_id>:<id>`
//! - `service_grant:grantee_idx:v1:<client_id>:<domain_id>:<id>`
//! - `service_grant:project_idx:v1:<project_id>:<client_id>:<domain_id>:<id>`
//!
//! The project index carries the grantee so the per-(project, client) cap
//! is a prefix count. Grant and index keys are written and removed in one
//! transaction. IDs never contain `:` (UUIDs and Keystone ids), so the key
//! segments split unambiguously.

use async_trait::async_trait;
use std::sync::Arc;

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core::service_grant::ServiceGrantProviderError;
use openstack_keystone_core::service_grant::backend::ServiceGrantBackend;
use openstack_keystone_core_types::service_grant::*;
use openstack_keystone_distributed_storage::{
    ApiStoreError, Metadata, StorageApi, StoreDataEnvelope, StoreError, StoreResponse,
    store_command::Mutation,
};

const PRIMARY: &str = "service_grant:v1:";
const ID_IDX: &str = "service_grant:id_idx:v1:";
const GRANTOR_IDX: &str = "service_grant:grantor_idx:v1:";
const GRANTEE_IDX: &str = "service_grant:grantee_idx:v1:";
const PROJECT_IDX: &str = "service_grant:project_idx:v1:";

/// Bridges the real storage (first violation is an `Err(Conflict)`) and
/// `MockStorage` (violations returned as data); mirrors the helper of the
/// other Raft drivers.
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

/// A `(domain_id, id)` coordinate recovered from an index key.
type Coordinate = (String, String);

/// Raft service grant backend.
#[derive(Default)]
pub struct RaftServiceGrantBackend {}

impl RaftServiceGrantBackend {
    fn primary_key(domain_id: &str, id: &str) -> String {
        format!("{PRIMARY}{domain_id}:{id}")
    }

    fn index_keys(grant: &ServiceGrant) -> Vec<String> {
        let (domain, id) = (&grant.domain_id, &grant.id);
        vec![
            format!("{ID_IDX}{id}:{domain}"),
            format!("{GRANTOR_IDX}{}:{domain}:{id}", grant.grantor_user_id),
            format!("{GRANTEE_IDX}{}:{domain}:{id}", grant.grantee.client_id()),
            format!(
                "{PROJECT_IDX}{}:{}:{domain}:{id}",
                grant.target.project_id(),
                grant.grantee.client_id()
            ),
        ]
    }

    /// The last two `:`-separated segments of each key under `prefix`,
    /// as `(domain_id, id)` (the id index stores them reversed).
    async fn coordinates(
        storage: &dyn StorageApi,
        prefix: &str,
        reversed: bool,
    ) -> Result<Vec<Coordinate>, StoreError> {
        Ok(storage
            .prefix_index(prefix.as_bytes())
            .await?
            .into_iter()
            .filter_map(|key| {
                let rest = key.get(prefix.len()..)?;
                let mut parts = rest.rsplitn(3, ':');
                let last = parts.next()?.to_string();
                let before = parts.next()?.to_string();
                Some(if reversed {
                    (last, before)
                } else {
                    (before, last)
                })
            })
            .collect())
    }

    async fn get_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        id: &str,
    ) -> Result<Option<StoreDataEnvelope<ServiceGrant>>, StoreError> {
        Ok(storage
            .get_by_key(Self::primary_key(domain_id, id).as_bytes(), None)
            .await?
            .map(|env| env.try_deserialize::<ServiceGrant>())
            .transpose()?)
    }

    async fn get_by_id_impl(
        &self,
        storage: &dyn StorageApi,
        id: &str,
    ) -> Result<Option<ServiceGrant>, StoreError> {
        // `<id>:<domain>`: the id index reverses the coordinate so that the
        // prefix `<id>:` matches exactly one grant.
        let prefix = format!("{ID_IDX}{id}:");
        for key in storage.prefix_index(prefix.as_bytes()).await? {
            let Some(domain_id) = key.get(prefix.len()..) else {
                continue;
            };
            if let Some(env) = self.get_impl(storage, domain_id, id).await? {
                return Ok(Some(env.data));
            }
        }
        Ok(None)
    }

    async fn create_impl(
        &self,
        storage: &dyn StorageApi,
        grant: ServiceGrant,
    ) -> Result<ServiceGrant, StoreError> {
        let primary_key = Self::primary_key(&grant.domain_id, &grant.id);
        let mut mutations = vec![Mutation::create_if_absent(
            primary_key.clone(),
            grant.clone(),
            Metadata::new(),
            None::<&str>,
        )?];
        mutations.extend(
            Self::index_keys(&grant)
                .into_iter()
                .map(Mutation::set_index),
        );
        let id = grant.id.clone();
        require_no_conflict(storage.transaction(mutations).await, move || {
            StoreError::Conflict {
                subject: primary_key,
                description: format!("service grant {id} already exists"),
            }
        })?;
        Ok(grant)
    }

    async fn delete_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        id: &str,
    ) -> Result<(), StoreError> {
        let Some(curr) = self.get_impl(storage, domain_id, id).await? else {
            return Err(not_found());
        };
        let mut mutations = vec![Mutation::remove(
            Self::primary_key(domain_id, id),
            None::<&str>,
            Some(curr.metadata.revision),
        )];
        mutations.extend(
            Self::index_keys(&curr.data)
                .into_iter()
                .map(Mutation::remove_index),
        );
        let subject = Self::primary_key(domain_id, id);
        require_no_conflict(storage.transaction(mutations).await, move || {
            StoreError::Conflict {
                subject,
                description: "service grant changed concurrently".to_string(),
            }
        })?;
        Ok(())
    }

    async fn list_impl(
        &self,
        storage: &dyn StorageApi,
        params: &ServiceGrantListParameters,
    ) -> Result<Vec<ServiceGrant>, StoreError> {
        // Resolve the narrowest index the filters name, then apply every
        // filter to the loaded records, so the value a caller filters on is
        // the value of the record returned.
        let mut grants: Vec<ServiceGrant> = Vec::new();
        let coordinates = if let Some(user_id) = &params.grantor_user_id {
            Some(Self::coordinates(storage, &format!("{GRANTOR_IDX}{user_id}:"), false).await?)
        } else if let Some(client_id) = &params.grantee_client_id {
            Some(Self::coordinates(storage, &format!("{GRANTEE_IDX}{client_id}:"), false).await?)
        } else if let Some(project_id) = &params.project_id {
            Some(Self::coordinates(storage, &format!("{PROJECT_IDX}{project_id}:"), false).await?)
        } else {
            None
        };
        match coordinates {
            Some(coordinates) => {
                for (domain_id, id) in coordinates {
                    if let Some(env) = self.get_impl(storage, &domain_id, &id).await? {
                        grants.push(env.data);
                    }
                }
            }
            None => {
                let prefix = match &params.domain_id {
                    Some(domain_id) => format!("{PRIMARY}{domain_id}:"),
                    None => PRIMARY.to_string(),
                };
                for (_, env) in storage.prefix(prefix.as_bytes(), None).await? {
                    grants.push(env.try_deserialize::<ServiceGrant>()?.data);
                }
            }
        }
        grants.retain(|g| {
            params.domain_id.as_ref().is_none_or(|d| &g.domain_id == d)
                && params
                    .grantor_user_id
                    .as_ref()
                    .is_none_or(|u| &g.grantor_user_id == u)
                && params
                    .grantee_client_id
                    .as_ref()
                    .is_none_or(|c| g.grantee.client_id() == c)
                && params
                    .project_id
                    .as_ref()
                    .is_none_or(|p| g.target.project_id() == p)
                && params.enabled.is_none_or(|e| g.enabled == e)
        });

        grants.sort_by(|a, b| a.id.cmp(&b.id));
        grants.dedup_by(|a, b| a.id == b.id);
        if let Some(marker) = &params.pagination.marker {
            if params.pagination.page_reverse {
                grants.retain(|x| x.id.as_str() < marker.as_str());
            } else {
                grants.retain(|x| x.id.as_str() > marker.as_str());
            }
        }
        if let Some(limit) = params.pagination.limit {
            let limit = usize::try_from(limit)
                .unwrap_or(usize::MAX)
                .saturating_add(1);
            if params.pagination.page_reverse {
                if grants.len() > limit {
                    grants = grants.split_off(grants.len() - limit);
                }
            } else {
                grants.truncate(limit);
            }
        }
        Ok(grants)
    }

    async fn count_impl(
        &self,
        storage: &dyn StorageApi,
        project_id: &str,
        grantee_client_id: Option<&str>,
    ) -> Result<usize, StoreError> {
        let prefix = match grantee_client_id {
            Some(client_id) => format!("{PROJECT_IDX}{project_id}:{client_id}:"),
            None => format!("{PROJECT_IDX}{project_id}:"),
        };
        Ok(storage.prefix_index(prefix.as_bytes()).await?.len())
    }

    async fn update_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        id: &str,
        update: ServiceGrantUpdate,
        expected_version: u64,
    ) -> Result<ServiceGrant, StoreError> {
        let key = Self::primary_key(domain_id, id);
        let curr = self
            .get_impl(storage, domain_id, id)
            .await?
            .ok_or_else(not_found)?;
        if curr.data.version != expected_version {
            return Err(StoreError::Conflict {
                subject: key,
                description: format!(
                    "service grant {id} is at version {}, not {expected_version}",
                    curr.data.version
                ),
            });
        }
        let new = curr.data.with_update(update);
        storage
            .set_value(
                key,
                StoreDataEnvelope {
                    data: rmp_serde::to_vec(&new)?,
                    metadata: curr.metadata.new_revision(),
                },
                None,
                Some(curr.metadata.revision),
            )
            .await?;
        Ok(new)
    }
}

/// Sentinel for a missing record, mapped by [`map_err`].
fn not_found() -> StoreError {
    StoreError::IO {
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    }
}

/// Map a storage error to the provider error.
fn map_err(e: StoreError, id: &str) -> ServiceGrantProviderError {
    match e {
        StoreError::IO { source } if source.kind() == std::io::ErrorKind::NotFound => {
            ServiceGrantProviderError::NotFound(id.to_string())
        }
        StoreError::Conflict { description, .. } => {
            ServiceGrantProviderError::Conflict(description)
        }
        e => ServiceGrantProviderError::raft(e),
    }
}

fn storage(state: &ServiceState) -> Result<&dyn StorageApi, ServiceGrantProviderError> {
    state
        .storage
        .as_deref()
        .map(|s| s as &dyn StorageApi)
        .ok_or(ServiceGrantProviderError::RaftNotAvailable)
}

#[async_trait]
impl ServiceGrantBackend for RaftServiceGrantBackend {
    #[tracing::instrument(name = "driver.raft.service_grant.create", level = "debug", skip_all)]
    async fn create_service_grant(
        &self,
        state: &ServiceState,
        grant: ServiceGrant,
    ) -> Result<ServiceGrant, ServiceGrantProviderError> {
        let id = grant.id.clone();
        self.create_impl(storage(state)?, grant)
            .await
            .map_err(|e| map_err(e, &id))
    }

    #[tracing::instrument(name = "driver.raft.service_grant.delete", level = "debug", skip_all, fields(domain_id = %domain_id, id = %id))]
    async fn delete_service_grant<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        id: &'a str,
    ) -> Result<(), ServiceGrantProviderError> {
        self.delete_impl(storage(state)?, domain_id, id)
            .await
            .map_err(|e| map_err(e, id))
    }

    #[tracing::instrument(name = "driver.raft.service_grant.get", level = "debug", skip_all, fields(domain_id = %domain_id, id = %id))]
    async fn get_service_grant<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        id: &'a str,
    ) -> Result<Option<ServiceGrant>, ServiceGrantProviderError> {
        Ok(self
            .get_impl(storage(state)?, domain_id, id)
            .await
            .map_err(|e| map_err(e, id))?
            .map(|env| env.data))
    }

    #[tracing::instrument(name = "driver.raft.service_grant.get_by_id", level = "debug", skip_all, fields(id = %id))]
    async fn get_service_grant_by_id<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<ServiceGrant>, ServiceGrantProviderError> {
        self.get_by_id_impl(storage(state)?, id)
            .await
            .map_err(|e| map_err(e, id))
    }

    #[tracing::instrument(name = "driver.raft.service_grant.list", level = "debug", skip_all, fields(params = ?params))]
    async fn list_service_grants(
        &self,
        state: &ServiceState,
        params: &ServiceGrantListParameters,
    ) -> Result<Vec<ServiceGrant>, ServiceGrantProviderError> {
        self.list_impl(storage(state)?, params)
            .await
            .map_err(ServiceGrantProviderError::raft)
    }

    #[tracing::instrument(name = "driver.raft.service_grant.count", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn count_service_grants<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        grantee_client_id: Option<&'a str>,
    ) -> Result<usize, ServiceGrantProviderError> {
        self.count_impl(storage(state)?, project_id, grantee_client_id)
            .await
            .map_err(ServiceGrantProviderError::raft)
    }

    #[tracing::instrument(name = "driver.raft.service_grant.update", level = "debug", skip_all, fields(domain_id = %domain_id, id = %id))]
    async fn update_service_grant<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        id: &'a str,
        update: ServiceGrantUpdate,
        expected_version: u64,
    ) -> Result<ServiceGrant, ServiceGrantProviderError> {
        self.update_impl(storage(state)?, domain_id, id, update, expected_version)
            .await
            .map_err(|e| map_err(e, id))
    }
}

/// Linkage anchor -- see ADR-0018.
#[allow(dead_code)]
pub fn anchor() {}

inventory::submit! {
    BackendRegistration::<dyn ServiceGrantBackend> {
        name: "raft",
        selected: |_| true,
        build: |_cfg| Box::pin(async {
            Ok(Arc::new(RaftServiceGrantBackend::default()) as Arc<dyn ServiceGrantBackend>)
        }),
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use openstack_keystone_distributed_storage::mock::MockStorage;

    use super::*;

    fn grant(id: &str, domain: &str, user: &str, client: &str, project: &str) -> ServiceGrant {
        ServiceGrant {
            id: id.into(),
            version: 1,
            domain_id: domain.into(),
            grantor_user_id: user.into(),
            grantee: Grantee::Client {
                client_id: client.into(),
                client_domain_id: domain.into(),
            },
            target: GrantTarget::Project {
                project_id: project.into(),
                project_domain_id: "pdid".into(),
            },
            role_ids: vec!["member".into()],
            expires_at: None,
            description: Some("backup".into()),
            enabled: true,
            created_at: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            last_redeemed_at: None,
            disabled_reason: None,
        }
    }

    async fn seeded() -> (RaftServiceGrantBackend, MockStorage) {
        let backend = RaftServiceGrantBackend::default();
        let storage = MockStorage::default();
        for g in [
            grant("g1", "d1", "u1", "c1", "p1"),
            grant("g2", "d1", "u1", "c2", "p1"),
            grant("g3", "d1", "u2", "c1", "p2"),
            grant("g4", "d2", "u3", "c1", "p3"),
        ] {
            backend.create_impl(&storage, g).await.unwrap();
        }
        (backend, storage)
    }

    #[test]
    fn test_msgpack_roundtrip() {
        let mut g = grant("g1", "d1", "u1", "c1", "p1");
        g.expires_at = Some(Utc::now());
        g.disabled_reason = Some(DisabledReason::TargetDisabled);
        let bytes = rmp_serde::to_vec(&g).unwrap();
        let parsed: ServiceGrant = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed, g);
    }

    #[tokio::test]
    async fn test_create_get_and_duplicate() {
        let (backend, storage) = seeded().await;
        let got = backend
            .get_impl(&storage, "d1", "g1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.data, grant("g1", "d1", "u1", "c1", "p1"));
        assert!(
            backend
                .get_impl(&storage, "d2", "g1")
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            backend
                .create_impl(&storage, grant("g1", "d1", "u9", "c9", "p9"))
                .await,
            Err(StoreError::Conflict { .. })
        ));
    }

    #[tokio::test]
    async fn test_get_by_id() {
        let (backend, storage) = seeded().await;
        let got = backend
            .get_by_id_impl(&storage, "g4")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.domain_id, "d2");
        assert!(
            backend
                .get_by_id_impl(&storage, "g")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_list_filters() {
        let (backend, storage) = seeded().await;
        let ids = |v: Vec<ServiceGrant>| v.into_iter().map(|g| g.id).collect::<Vec<_>>();
        let list = |params: ServiceGrantListParameters| {
            let backend = &backend;
            let storage = &storage;
            async move { ids(backend.list_impl(storage, &params).await.unwrap()) }
        };
        assert_eq!(
            list(ServiceGrantListParameters::default()).await,
            ["g1", "g2", "g3", "g4"]
        );
        assert_eq!(
            list(ServiceGrantListParameters {
                grantor_user_id: Some("u1".into()),
                ..Default::default()
            })
            .await,
            ["g1", "g2"]
        );
        assert_eq!(
            list(ServiceGrantListParameters {
                grantee_client_id: Some("c1".into()),
                domain_id: Some("d1".into()),
                ..Default::default()
            })
            .await,
            ["g1", "g3"]
        );
        assert_eq!(
            list(ServiceGrantListParameters {
                project_id: Some("p1".into()),
                grantee_client_id: Some("c2".into()),
                ..Default::default()
            })
            .await,
            ["g2"]
        );
        assert_eq!(
            list(ServiceGrantListParameters {
                domain_id: Some("d2".into()),
                ..Default::default()
            })
            .await,
            ["g4"]
        );
        // A prefix of one id must not match another (`u1` vs `u10`).
        backend
            .create_impl(&storage, grant("g5", "d1", "u10", "c1", "p1"))
            .await
            .unwrap();
        assert_eq!(
            list(ServiceGrantListParameters {
                grantor_user_id: Some("u1".into()),
                ..Default::default()
            })
            .await,
            ["g1", "g2"]
        );
    }

    #[tokio::test]
    async fn test_count() {
        let (backend, storage) = seeded().await;
        assert_eq!(backend.count_impl(&storage, "p1", None).await.unwrap(), 2);
        assert_eq!(
            backend
                .count_impl(&storage, "p1", Some("c1"))
                .await
                .unwrap(),
            1
        );
        assert_eq!(backend.count_impl(&storage, "p9", None).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_update_checks_version() {
        let (backend, storage) = seeded().await;
        let update = ServiceGrantUpdate {
            enabled: Some(false),
            disabled_reason: Some(DisabledReason::Revoked),
            ..Default::default()
        };
        let updated = backend
            .update_impl(&storage, "d1", "g1", update.clone(), 1)
            .await
            .unwrap();
        assert_eq!(updated.version, 2);
        assert!(!updated.enabled);
        assert!(matches!(
            backend
                .update_impl(&storage, "d1", "g1", update.clone(), 1)
                .await,
            Err(StoreError::Conflict { .. })
        ));
        assert!(matches!(
            map_err(
                backend
                    .update_impl(&storage, "d1", "missing", update, 1)
                    .await
                    .unwrap_err(),
                "missing"
            ),
            ServiceGrantProviderError::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn test_delete_removes_indexes() {
        let (backend, storage) = seeded().await;
        backend.delete_impl(&storage, "d1", "g1").await.unwrap();
        assert!(
            backend
                .get_impl(&storage, "d1", "g1")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .get_by_id_impl(&storage, "g1")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(backend.count_impl(&storage, "p1", None).await.unwrap(), 1);
        assert!(matches!(
            backend.delete_impl(&storage, "d1", "g1").await,
            Err(StoreError::IO { .. })
        ));
    }
}
