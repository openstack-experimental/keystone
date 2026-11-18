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

//! Replicated per-site KEK registry (ADR 0045 §11.2).
//!
//! The list of sites a new DEK envelope is wrapped for lives in `meta` under
//! [`META_SITES`], so it travels with snapshots and backups. [`SetSites`]
//! replaces it on every node and re-wraps the envelopes this node stores, so
//! a site that was just added can adopt the DEKs through `FetchDek` or a
//! snapshot.
//!
//! [`SetSites`]: crate::store_command::MutationInner::SetSites

use openstack_keystone_storage_crypto::SiteEntry;

use super::*;

/// Fjall meta key holding the msgpack-encoded `Vec<SiteRecord>`.
pub(crate) const META_SITES: &[u8] = b"_meta:sites";

impl From<&SiteRecord> for SiteEntry {
    fn from(r: &SiteRecord) -> Self {
        SiteEntry {
            name: r.name.clone(),
            public_key_der: r.public_key_der.clone(),
            key_version: r.key_version,
        }
    }
}

impl From<&SiteEntry> for SiteRecord {
    fn from(e: &SiteEntry) -> Self {
        SiteRecord {
            name: e.name.clone(),
            public_key_der: e.public_key_der.clone(),
            key_version: e.key_version,
        }
    }
}

impl FjallStateMachine {
    /// The replicated site list, if one was ever set.
    pub fn replicated_sites(&self) -> Result<Option<Vec<SiteRecord>>, StoreError> {
        let Some(raw) = self.meta.get(META_SITES)? else {
            return Ok(None);
        };
        let sites = rmp_serde::from_slice(raw.as_ref())
            .map_err(|e| StoreError::Other(eyre::eyre!("decoding {META_SITES:?}: {e}")))?;
        Ok(Some(sites))
    }

    /// Makes the in-memory registry follow the replicated list, which wins
    /// over the configured seed. Called at start-up and after a snapshot or
    /// backup replaced `meta`.
    pub(super) fn reload_site_registry(&self) -> Result<(), StoreError> {
        let (Some(kek), Some(sites)) = (self.kek.as_site_kek(), self.replicated_sites()?) else {
            return Ok(());
        };
        kek.registry()
            .replace(sites.iter().map(SiteEntry::from).collect());
        Ok(())
    }

    /// Re-wraps every stored DEK envelope for `sites`, keyed by the old
    /// envelope. Runs before the apply takes its lifecycle lock because the
    /// site key may be a remote key store. An envelope this node cannot open
    /// (for instance one that never included its site) is left out and
    /// logged: failing the apply would take the node down for a record it
    /// could not read anyway.
    pub(super) async fn rewrap_site_envelopes(
        &self,
        sites: &[SiteRecord],
    ) -> Result<HashMap<Vec<u8>, Vec<u8>>, StoreError> {
        let mut out = HashMap::new();
        let Some(kek) = self.kek.as_site_kek() else {
            return Ok(out);
        };
        let entries: Vec<SiteEntry> = sites.iter().map(SiteEntry::from).collect();
        let mut envelopes: Vec<Vec<u8>> = Vec::new();
        if let Some(cur) = self.meta.get(META_DEK_CURRENT)?
            && cur.len() > 4
        {
            envelopes.push(cur[4..].to_vec());
        }
        for prefix in [
            DEK_RETIRED_PREFIX,
            DEK_REVOKED_PENDING_PREFIX,
            DEK_SHADOW_PREFIX,
        ] {
            for item in self.meta.prefix(prefix.as_bytes()) {
                let (_, value) = item.into_inner()?;
                envelopes.push(value.to_vec());
            }
        }
        for old in envelopes {
            match kek.rewrap_for(&entries, &old).await {
                Ok(new) => {
                    out.insert(old, new);
                }
                Err(e) => tracing::error!(
                    error = %e,
                    "cannot re-wrap a DEK envelope for the new site list"
                ),
            }
        }
        Ok(out)
    }

    /// Stages the new site list and the re-wrapped DEK envelopes into
    /// `batch`. Returns the list to install in the in-memory registry once
    /// the batch commits.
    ///
    /// An envelope this node cannot open (for instance one that never
    /// included its site) is left as it is and logged: failing the apply
    /// would take the node down for a record it could not read anyway.
    pub(super) fn stage_site_registry(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        sites: &[SiteRecord],
        rewrapped: &HashMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Vec<SiteEntry>, StoreError> {
        let entries: Vec<SiteEntry> = sites.iter().map(SiteEntry::from).collect();
        let encoded = rmp_serde::to_vec(sites)
            .map_err(|e| StoreError::Other(eyre::eyre!("encoding the site list: {e}")))?;
        batch.insert(&self.meta, META_SITES, encoded);

        if self.kek.as_site_kek().is_none() {
            tracing::warn!(
                "SetSites applied on a node whose KEK provider is not per_site; the list is \
                 stored but wraps nothing"
            );
            return Ok(entries);
        }
        let rewrap = |wrapped: &[u8]| rewrapped.get(wrapped).cloned();
        if let Some(cur) = self.meta.get(META_DEK_CURRENT)?
            && cur.len() > 4
            && let Some(w) = rewrap(&cur[4..])
        {
            let mut persisted = cur[..4].to_vec();
            persisted.extend_from_slice(&w);
            batch.insert(&self.meta, META_DEK_CURRENT, persisted);
        }
        for prefix in [
            DEK_RETIRED_PREFIX,
            DEK_REVOKED_PENDING_PREFIX,
            DEK_SHADOW_PREFIX,
        ] {
            for item in self.meta.prefix(prefix.as_bytes()) {
                let (key, value) = item.into_inner()?;
                if let Some(w) = rewrap(&value) {
                    batch.insert(&self.meta, key, w);
                }
            }
        }
        Ok(entries)
    }
}
