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

//! Automatic DEK rotation (ADR 0016-v2 §6).
//!
//! The Raft leader rotates the DEK on its own when the current epoch is
//! older than `[distributed_storage] dek_rotation_days`, or when the log
//! nonce counter of the current epoch has used 90% of its `2^31` space (the
//! node stops accepting writes at `2^31`, see
//! [`NonceManager`](openstack_keystone_storage_crypto::NonceManager)). The
//! rotation is the same `InstallDek` proposal `keystone-manage storage
//! rotate-dek` makes.

use openstack_keystone_storage_crypto::generate_dek;

use super::*;

/// Interval between two automatic-rotation checks.
pub(super) const DEK_ROTATION_CHECK_INTERVAL: Duration = Duration::from_secs(300);

/// Audit actor of automatic rotations.
const AUTOMATIC_ROTATION_ACTOR: &str = "system:dek-rotation";

/// Why the DEK is rotated automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationTrigger {
    /// The current epoch is older than `dek_rotation_days`.
    Age {
        /// When the current epoch was installed (Unix seconds).
        installed_at: u64,
    },
    /// The log nonce counter of the current epoch reached 90% of its space.
    NonceVolume {
        /// Next counter value of the current epoch.
        counter: u32,
    },
}

impl RotationTrigger {
    fn reason(&self) -> &'static str {
        match self {
            Self::Age { .. } => "age",
            Self::NonceVolume { .. } => "log_nonce_volume",
        }
    }
}

/// Decide whether the DEK must be rotated.
///
/// - `now`, `installed_at`: Unix seconds; `installed_at` is `None` when the
///   install time of the current epoch is unknown.
/// - `rotation_days`: `0` disables the age trigger.
/// - `nonce_epoch`, `nonce_counter`, `nonce_due`: the log nonce manager's
///   state; it only counts for the current epoch (`current_version`).
pub(crate) fn rotation_trigger(
    now: u64,
    installed_at: Option<u64>,
    rotation_days: u32,
    current_version: u32,
    nonce_epoch: u32,
    nonce_counter: u32,
    nonce_due: bool,
) -> Option<RotationTrigger> {
    if nonce_due && nonce_epoch == current_version {
        return Some(RotationTrigger::NonceVolume {
            counter: nonce_counter,
        });
    }
    let installed_at = installed_at?;
    let max_age = u64::from(rotation_days) * 24 * 60 * 60;
    (rotation_days > 0 && now.saturating_sub(installed_at) >= max_age)
        .then_some(RotationTrigger::Age { installed_at })
}

impl Storage {
    /// Rotation due on this node now, if it is the leader and no emergency
    /// rotation is waiting for its confirmation.
    pub fn automatic_rotation_due(&self) -> Option<RotationTrigger> {
        if self.current_leader() != Some(self.node_id) {
            return None;
        }
        if !self
            .pending_rotations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty()
        {
            return None;
        }
        let (nonce_epoch, nonce_counter, nonce_due) = {
            let mgr = self.log_nonce.lock().unwrap_or_else(|p| p.into_inner());
            (mgr.epoch(), mgr.counter(), mgr.rotation_due())
        };
        let sm = &self.state_machine_store;
        rotation_trigger(
            crate::store::state_machine::unix_now(),
            sm.dek_installed_at(),
            self.dek_rotation_days,
            sm.current_dek_version(),
            nonce_epoch,
            nonce_counter,
            nonce_due,
        )
    }

    /// Propose a new DEK through Raft for `trigger`.
    ///
    /// Returns `Ok(false)` when this node is no longer the leader or another
    /// rotation committed the next version first.
    pub async fn rotate_dek_automatically(
        &self,
        trigger: RotationTrigger,
    ) -> Result<bool, StoreError> {
        let current_version = self.state_machine_store.current_dek_version();
        let new_version = current_version
            .checked_add(1)
            .ok_or_else(|| StoreError::Other(eyre!("DEK version space exhausted")))?;
        let wrapped_dek = self
            .kek
            .wrap_dek(generate_dek().as_bytes())
            .map_err(|e| StoreError::Other(eyre!("failed to wrap new DEK: {e}")))?;
        let cmd = StoreCommand::Transaction(vec![MutationInner::InstallDek {
            wrapped_dek,
            dek_version: new_version,
            is_emergency: false,
        }]);
        let payload = crate::pb::api::CommandRequest::try_from(cmd)
            .map_err(|e| StoreError::Other(eyre!(e)))?;
        let response = match self.raft.client_write(payload).await {
            Ok(response) => response,
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(_))) => return Ok(false),
            Err(other) => Err(other)?,
        };
        if !response.data.violations.is_empty() {
            tracing::info!(
                new_version,
                "automatic DEK rotation superseded by a concurrent rotation"
            );
            return Ok(false);
        }

        let details = match trigger {
            RotationTrigger::Age { installed_at } => serde_json::json!({
                "previous_version": current_version,
                "trigger": trigger.reason(),
                "installed_at": installed_at,
                "dek_rotation_days": self.dek_rotation_days,
            }),
            RotationTrigger::NonceVolume { counter } => serde_json::json!({
                "previous_version": current_version,
                "trigger": trigger.reason(),
                "log_nonce_counter": counter,
            }),
        };
        self.audit_forwarder.emit(AuditRecord::now(
            "DEK_ROTATION",
            AUTOMATIC_ROTATION_ACTOR,
            self.node_id,
            new_version,
            details,
        ));
        tracing::info!(
            previous_version = current_version,
            new_version,
            trigger = trigger.reason(),
            "automatic DEK rotation committed to Raft log"
        );
        Ok(true)
    }
}

/// Spawn the leader-only automatic rotation check. Holds a weak reference
/// so it never keeps `Storage` alive on its own.
pub(super) fn spawn_dek_rotation_task(storage: &Arc<Storage>) {
    let storage_weak = Arc::downgrade(storage);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(DEK_ROTATION_CHECK_INTERVAL);
        loop {
            interval.tick().await;
            let Some(storage) = storage_weak.upgrade() else {
                break;
            };
            let Some(trigger) = storage.automatic_rotation_due() else {
                continue;
            };
            if let Err(e) = storage.rotate_dek_automatically(trigger).await {
                tracing::warn!(
                    error = %e,
                    trigger = trigger.reason(),
                    "automatic DEK rotation failed; retrying on the next check"
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 60 * 60;

    #[test]
    fn age_trigger_fires_after_rotation_days() {
        let installed = 1_000_000;
        assert_eq!(
            None,
            rotation_trigger(
                installed + 90 * DAY - 1,
                Some(installed),
                90,
                3,
                3,
                0,
                false
            )
        );
        assert_eq!(
            Some(RotationTrigger::Age {
                installed_at: installed
            }),
            rotation_trigger(installed + 90 * DAY, Some(installed), 90, 3, 3, 0, false)
        );
    }

    #[test]
    fn age_trigger_disabled_by_zero_days() {
        assert_eq!(None, rotation_trigger(u64::MAX, Some(0), 0, 3, 3, 0, false));
    }

    #[test]
    fn age_trigger_needs_install_time() {
        assert_eq!(None, rotation_trigger(u64::MAX, None, 90, 3, 3, 0, false));
    }

    #[test]
    fn nonce_trigger_fires_for_current_epoch_only() {
        assert_eq!(
            Some(RotationTrigger::NonceVolume { counter: 42 }),
            rotation_trigger(0, Some(0), 0, 3, 3, 42, true)
        );
        // The manager still holds the previous epoch until the next log
        // entry is written under the new one.
        assert_eq!(None, rotation_trigger(0, Some(0), 0, 4, 3, 42, true));
    }
}
