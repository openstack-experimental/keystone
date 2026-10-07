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

//! Read-only snapshot of this node's storage-encryption state, backing the
//! `StorageStatus` admin RPC (issue #1305).

use openstack_keystone_storage_crypto::nonce::persisted_counter;

use super::*;
use crate::types::FjallNoncePersistence;

/// This node's DEK, quarantine and nonce state at one point in time.
///
/// Each field is read independently (no global lock), so a rotation or
/// quarantine landing mid-read can show a mix of before/after values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EncryptionStatus {
    /// The active DEK epoch.
    pub dek_version: u32,
    /// Retired epochs still held for reading, ascending.
    pub retired_dek_versions: Vec<u32>,
    /// Revoked epochs, ascending.
    pub revoked_dek_versions: Vec<u32>,
    /// Partitions whose reads are blocked on this node, sorted.
    pub quarantined_partitions: Vec<String>,
    /// Every persisted `(partition, reporting node)` quarantine marker,
    /// sorted.
    pub quarantine_records: Vec<(String, u64)>,
    /// Persisted log-nonce reservation counter of this node.
    pub nonce_counter: u64,
}

impl FjallStateMachine {
    /// Collects this node's [`EncryptionStatus`].
    pub fn encryption_status(&self) -> Result<EncryptionStatus, StoreError> {
        let dek_version = self.dek.read().unwrap_or_else(|p| p.into_inner()).version;
        let retired_dek_versions = self
            .old_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .copied()
            .collect();
        let mut revoked_dek_versions: Vec<u32> = self
            .revoked_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .copied()
            .collect();
        revoked_dek_versions.sort_unstable();
        let mut quarantined_partitions: Vec<String> = self
            .quarantine
            .quarantined
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect();
        quarantined_partitions.sort_unstable();

        let mut quarantine_records = Vec::new();
        for item in self.meta.prefix(QUARANTINE_META_PREFIX.as_bytes()) {
            let (key, _) = item.into_inner()?;
            let Some(rest) = std::str::from_utf8(&key)
                .ok()
                .and_then(|k| k.strip_prefix(QUARANTINE_META_PREFIX))
            else {
                continue;
            };
            if let Some((partition, node)) = rest.rsplit_once(':')
                && let Ok(node) = node.parse::<u64>()
            {
                quarantine_records.push((partition.to_string(), node));
            }
        }
        quarantine_records.sort_unstable();

        let persistence = FjallNoncePersistence {
            keyspace: self.meta.clone(),
            db: self.db.clone(),
        };
        let nonce_counter = persisted_counter(&persistence, self.node_id, dek_version)
            .map_err(|e| StoreError::Other(eyre::eyre!("cannot read nonce counter: {e}")))?;

        Ok(EncryptionStatus {
            dek_version,
            retired_dek_versions,
            revoked_dek_versions,
            quarantined_partitions,
            quarantine_records,
            nonce_counter,
        })
    }
}
