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

//! The [`RaftStateMachine`] implementation: applying committed entries.

use super::*;

impl RaftStateMachine<TypeConfig> for Arc<FjallStateMachine> {
    type SnapshotData = Vec<u8>;
    type SnapshotBuilder = Self;

    #[tracing::instrument(skip(self))]
    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogIdOf<TypeConfig>>, StoredMembershipOf<TypeConfig>), io::Error> {
        self.get_meta().map_err(|e| io::Error::other(e.to_string()))
    }

    #[tracing::instrument(skip(self))]
    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    #[tracing::instrument(skip(self))]
    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMetaOf<TypeConfig>,
        snapshot: Vec<u8>,
    ) -> Result<(), io::Error> {
        tracing::info!(
            { snapshot_size = snapshot.len() },
            "decoding snapshot for installation"
        );

        let payload: SnapshotPayload = deserialize(snapshot.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        check_snapshot_format_version(payload.version)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let payload_clone = payload.clone();

        let last_applied_bytes = meta
            .last_log_id
            .as_ref()
            .map(|log_id| {
                serialize(log_id)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
            })
            .transpose()?;

        let last_membership_bytes = serialize(&meta.last_membership)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let manifest = self.install_payload(
            payload,
            RaftBookkeeping::Install(last_applied_bytes, last_membership_bytes),
        )?;

        let snapshot_idx: u64 = rand::rng().random_range(0..1000);
        let snapshot_id = if let Some(last) = meta.last_log_id.as_ref() {
            format!(
                "{}-{}-{}",
                last.committed_leader_id(),
                last.index(),
                snapshot_idx
            )
        } else {
            format!("--{}", snapshot_idx)
        };

        let snapshot_file = SnapshotFile {
            meta: meta.clone(),
            payload: payload_clone,
        };
        let file_bytes = serialize(&snapshot_file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Encrypt the snapshot file at rest with the current BackupDek,
        // persist it, record it as the newest snapshot and GC stale files.
        self.persist_snapshot_file(&snapshot_id, &file_bytes, &manifest)?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<SnapshotOf<TypeConfig, Vec<u8>>>, io::Error> {
        // Try every retained snapshot file, newest first, falling back to
        // an older one if the newest turns out corrupt or undecryptable
        // (GitHub #1296 item 3) rather than refusing to start.
        for snapshot_id in self.snapshot_history()? {
            let snapshot_path = self.snapshot_dir.join(&snapshot_id);
            let disk_bytes = match fs::read(&snapshot_path) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            match decrypt_snapshot_file(
                &disk_bytes,
                &self.dek,
                &self.old_deks,
                &self.shadow_deks,
                &[],
            ) {
                Ok((snapshot_file, _, _)) => {
                    let data_bytes = rmp_serde::to_vec(&snapshot_file.payload)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    return Ok(Some(Snapshot {
                        meta: snapshot_file.meta,
                        snapshot: data_bytes,
                    }));
                }
                Err(e) => {
                    tracing::warn!(
                        snapshot_id,
                        error = %e,
                        "local snapshot file failed to decode; trying an older one"
                    );
                }
            }
        }
        tracing::warn!("no usable local snapshot file found on startup; starting without one");
        Ok(None)
    }

    #[tracing::instrument(skip(self, entries))]
    async fn apply<Strm>(&mut self, entries: Strm) -> Result<(), io::Error>
    where
        Strm: Stream<Item = Result<EntryResponder<TypeConfig>, io::Error>> + Unpin + OptionalSend,
    {
        let mut last_membership = None;
        let mut entries = entries;
        // Responders are collected here and only notified once the whole
        // stream is durable (see the single `persist(SyncAll)` at the end
        // of this function) — GitHub #1297 item 2: `apply()` used to call
        // `persist(SyncAll)` after every single entry, i.e. at least one
        // full-database fsync per committed write on every node; openraft
        // only requires the state machine to be durable relative to
        // `last_applied` once `apply()` returns, not after each entry
        // within the batch it was given, so a single fsync at the end
        // (after the log's own per-batch fsync in `append`) is sufficient.
        // Sending a responder before its entry's write is actually fsynced
        // would tell the caller "committed" ahead of durability, so every
        // responder must wait for that final persist too.
        let mut pending_responses: Vec<(
            openraft::storage::ApplyResponder<TypeConfig>,
            crate::ZeroizingResponse,
        )> = Vec::new();

        while let Some((entry, responder)) = entries.try_next().await? {
            // ADR 0031 `keystone_raft_apply_duration_seconds`: measures one
            // committed log entry's write/encrypt/commit latency, unlike
            // the read-through snapshot gauges in `prometheus_metrics`.
            // Excludes the batched `persist(SyncAll)` at the end of this
            // function, which now covers the whole stream rather than one
            // entry.
            let apply_start = Instant::now();
            // Held for this entry's whole processing+commit (there is no
            // further `.await` in this loop body until the next iteration),
            // so a concurrent `drop_keyspace` can't observe a keyspace as
            // empty mid-write and delete it out from under this commit.
            // `Option` so `RestoreApply` can release it: replacing the
            // keyspaces needs the write side of the same lock.
            let mut lifecycle_guard = Some(
                self.keyspace_lifecycle
                    .read()
                    .unwrap_or_else(|p| p.into_inner()),
            );
            let last_applied_log = entry.log_id();
            let mut batch = self.db.batch();
            let mut has_violations = false;
            let mut pending_dek_swap: Option<(Arc<DekEpoch>, bool)> = None;
            // See `PendingRotationMutation`: deferred the same way as
            // `pending_dek_swap` above.
            let mut pending_rotation_mutation: Option<PendingRotationMutation> = None;

            let response = if let Some(store_req) = entry.app_data {
                match StoreCommand::unpack(&store_req)? {
                    StoreCommand::RestoreChunk {
                        restore_id,
                        seq,
                        data,
                    } => {
                        if seq == 0 {
                            // A new restore supersedes any abandoned one.
                            for item in self.meta.prefix(RESTORE_STAGE_PREFIX.as_bytes()) {
                                if let Ok(key) = item.key() {
                                    batch.remove(&self.meta, key);
                                }
                            }
                        }
                        batch.insert(&self.meta, restore_stage_key(&restore_id, seq), data);
                        (None, vec![])
                    }
                    StoreCommand::RestoreAbort { restore_id } => {
                        for item in self.meta.prefix(restore_stage_prefix(&restore_id)) {
                            if let Ok(key) = item.key() {
                                batch.remove(&self.meta, key);
                            }
                        }
                        (None, vec![])
                    }
                    StoreCommand::RestoreApply {
                        restore_id,
                        chunks,
                        total_len,
                    } => {
                        drop(lifecycle_guard.take());
                        let violations = match self.apply_restore(&restore_id, chunks, total_len) {
                            Ok(()) => vec![],
                            Err(RestoreError::Rejected(description)) => {
                                tracing::error!(
                                    restore_id,
                                    description,
                                    "live restore rejected on apply"
                                );
                                vec![Violation {
                                    r#type: "RESTORE_FAILED".to_string(),
                                    subject: restore_id,
                                    description,
                                }]
                            }
                            Err(RestoreError::Fatal(e)) => return Err(e),
                        };
                        has_violations = !violations.is_empty();
                        (None, violations)
                    }
                    StoreCommand::Transaction(mutations) => {
                        let mut violations: Vec<Violation> = Vec::new();
                        for mutation in mutations {
                            match mutation {
                                MutationInner::Remove {
                                    key,
                                    keyspace,
                                    expected_revision,
                                } => {
                                    if let Err(e) = check_keyspace_allowed(&keyspace) {
                                        violations.push(Violation {
                                            r#type: "RESERVED_KEYSPACE".to_string(),
                                            subject: String::from_utf8_lossy(&key).to_string(),
                                            description: e.to_string(),
                                        });
                                        continue;
                                    }

                                    if let Some(ephemeral_ks) = self.ephemeral.get(&keyspace) {
                                        if let Some(expected_revision) = expected_revision {
                                            let curr_revision = ephemeral_ks
                                                .get(&key)
                                                .map(|entry| entry.1.revision);
                                            if curr_revision.is_none_or(|r| r != expected_revision)
                                            {
                                                violations.push(Violation {
                                                    r#type: "CONFLICT".to_string(),
                                                    subject: String::from_utf8_lossy(&key)
                                                        .to_string(),
                                                    description: format!(
                                                        "Current revision is {curr_revision:?} \
                                                         while {expected_revision} was expected",
                                                    ),
                                                });
                                                continue;
                                            }
                                        }
                                        ephemeral_ks.remove(&key);
                                        continue;
                                    }

                                    if let Some(expected_revision) = expected_revision {
                                        let curr_meta = self
                                            .meta()
                                            .get(meta_key(&keyspace, &key))
                                            .map_err(|e| io::Error::other(e.to_string()))?
                                            .map(|x| Metadata::unpack(x.as_ref()))
                                            .transpose()
                                            .map_err(|e| io::Error::other(e.to_string()))?;
                                        if curr_meta
                                            .as_ref()
                                            .is_none_or(|x| x.revision != expected_revision)
                                        {
                                            violations.push(Violation {
                                                r#type: "CONFLICT".to_string(),
                                                subject: String::from_utf8_lossy(&key).to_string(),
                                                description: format!(
                                                    "Current revision is {:?} while {} was expected",
                                                    curr_meta.map(|x| x.revision),
                                                    expected_revision,
                                                ),
                                            });
                                        }
                                    }

                                    let ks = &self.keyspace(&keyspace)?;
                                    batch.remove(ks, key.clone());
                                    batch.remove(&self.meta, meta_key(&keyspace, &key));
                                }
                                MutationInner::RemoveIndex { key } => {
                                    batch.remove(&self.index, key.clone());
                                }
                                MutationInner::Set {
                                    key,
                                    keyspace,
                                    cipher,
                                    metadata,
                                    tier,
                                    expected_revision,
                                } => {
                                    if let Err(e) = check_keyspace_allowed(&keyspace) {
                                        violations.push(Violation {
                                            r#type: "RESERVED_KEYSPACE".to_string(),
                                            subject: String::from_utf8_lossy(&key).to_string(),
                                            description: e.to_string(),
                                        });
                                        continue;
                                    }

                                    if metadata.is_ephemeral {
                                        let ephemeral_ks =
                                            self.ephemeral.entry(keyspace.clone()).or_default();
                                        if let Some(expected_revision) = expected_revision {
                                            let curr_revision = ephemeral_ks
                                                .get(&key)
                                                .map(|entry| entry.1.revision);
                                            if curr_revision.is_none_or(|r| r != expected_revision)
                                            {
                                                violations.push(Violation {
                                                    r#type: "CONFLICT".to_string(),
                                                    subject: String::from_utf8_lossy(&key)
                                                        .to_string(),
                                                    description: format!(
                                                        "Current revision is {curr_revision:?} \
                                                         while {expected_revision} was expected",
                                                    ),
                                                });
                                                continue;
                                            }
                                        }
                                        ephemeral_ks.insert(key, (cipher, metadata));
                                        continue;
                                    }

                                    if let Some(expected_revision) = expected_revision {
                                        let curr_meta = self
                                            .meta()
                                            .get(meta_key(&keyspace, &key))
                                            .map_err(|e| io::Error::other(e.to_string()))?
                                            .map(|x| Metadata::unpack(x.as_ref()))
                                            .transpose()
                                            .map_err(|e| io::Error::other(e.to_string()))?;
                                        if curr_meta
                                            .as_ref()
                                            .is_none_or(|x| x.revision != expected_revision)
                                        {
                                            violations.push(Violation {
                                                r#type: "CONFLICT".to_string(),
                                                subject: String::from_utf8_lossy(&key).to_string(),
                                                description: format!(
                                                    "Current revision is {:?} while {} was expected",
                                                    curr_meta.map(|x| x.revision),
                                                    expected_revision,
                                                ),
                                            });
                                        }
                                    }

                                    let ks = self
                                        .keyspace(&keyspace)
                                        .map_err(|e| io::Error::other(e.to_string()))?;
                                    match self.encrypt_and_store(
                                        &ks,
                                        &key,
                                        keyspace.as_bytes(),
                                        tier,
                                        &cipher,
                                    ) {
                                        Ok((encrypted, dek_version)) => {
                                            batch.insert(&ks, key.clone(), encrypted);
                                            let mut meta_with_tier = metadata.clone();
                                            meta_with_tier.tier = DataTier::from(tier);
                                            meta_with_tier.dek_version = Some(dek_version);
                                            batch.insert(
                                                &self.meta,
                                                meta_key(&keyspace, &key),
                                                meta_with_tier
                                                    .pack()
                                                    .map_err(|e| io::Error::other(e.to_string()))?,
                                            );
                                        }
                                        Err(StoreError::Quarantined(p)) => {
                                            violations.push(Violation {
                                                r#type: "QUARANTINED".to_string(),
                                                subject: String::from_utf8_lossy(&key).to_string(),
                                                description: format!(
                                                    "partition '{p}' is quarantined"
                                                ),
                                            });
                                        }
                                        Err(StoreError::WriteRateExceeded(k, v)) => {
                                            violations.push(Violation {
                                                r#type: "WRITE_RATE_EXCEEDED".to_string(),
                                                subject: k,
                                                description: format!(
                                                    "write version {v} reached threshold \
                                                     {WRITE_RATE_THRESHOLD}; DEK rotation required"
                                                ),
                                            });
                                        }
                                        Err(e) => {
                                            return Err(io::Error::other(e.to_string()));
                                        }
                                    }
                                }
                                MutationInner::CreateIfAbsent {
                                    key,
                                    keyspace,
                                    cipher,
                                    metadata,
                                    tier,
                                } => {
                                    if let Err(e) = check_keyspace_allowed(&keyspace) {
                                        violations.push(Violation {
                                            r#type: "RESERVED_KEYSPACE".to_string(),
                                            subject: String::from_utf8_lossy(&key).to_string(),
                                            description: e.to_string(),
                                        });
                                        continue;
                                    }

                                    if metadata.is_ephemeral {
                                        let ephemeral_ks =
                                            self.ephemeral.entry(keyspace.clone()).or_default();
                                        if ephemeral_ks.contains_key(&key) {
                                            violations.push(Violation {
                                                r#type: "CONFLICT".to_string(),
                                                subject: String::from_utf8_lossy(&key).to_string(),
                                                description:
                                                    "key already exists (create_if_absent)"
                                                        .to_string(),
                                            });
                                            continue;
                                        }
                                        ephemeral_ks.insert(key, (cipher, metadata));
                                        continue;
                                    }

                                    let exists = self
                                        .meta()
                                        .get(meta_key(&keyspace, &key))
                                        .map_err(|e| io::Error::other(e.to_string()))?
                                        .is_some();
                                    if exists {
                                        violations.push(Violation {
                                            r#type: "CONFLICT".to_string(),
                                            subject: String::from_utf8_lossy(&key).to_string(),
                                            description: "key already exists (create_if_absent)"
                                                .to_string(),
                                        });
                                    }

                                    let ks = self
                                        .keyspace(&keyspace)
                                        .map_err(|e| io::Error::other(e.to_string()))?;
                                    match self.encrypt_and_store(
                                        &ks,
                                        &key,
                                        keyspace.as_bytes(),
                                        tier,
                                        &cipher,
                                    ) {
                                        Ok((encrypted, dek_version)) => {
                                            batch.insert(&ks, key.clone(), encrypted);
                                            let mut meta_with_tier = metadata.clone();
                                            meta_with_tier.tier = DataTier::from(tier);
                                            meta_with_tier.dek_version = Some(dek_version);
                                            batch.insert(
                                                &self.meta,
                                                meta_key(&keyspace, &key),
                                                meta_with_tier
                                                    .pack()
                                                    .map_err(|e| io::Error::other(e.to_string()))?,
                                            );
                                        }
                                        Err(StoreError::Quarantined(p)) => {
                                            violations.push(Violation {
                                                r#type: "QUARANTINED".to_string(),
                                                subject: String::from_utf8_lossy(&key).to_string(),
                                                description: format!(
                                                    "partition '{p}' is quarantined"
                                                ),
                                            });
                                        }
                                        Err(StoreError::WriteRateExceeded(k, v)) => {
                                            violations.push(Violation {
                                                r#type: "WRITE_RATE_EXCEEDED".to_string(),
                                                subject: k,
                                                description: format!(
                                                    "write version {v} reached threshold \
                                                     {WRITE_RATE_THRESHOLD}; DEK rotation required"
                                                ),
                                            });
                                        }
                                        Err(e) => {
                                            return Err(io::Error::other(e.to_string()));
                                        }
                                    }
                                }
                                MutationInner::SetIndex { key } => {
                                    batch.insert(&self.index, key, vec![]);
                                }
                                MutationInner::ClearQuarantine { partition } => {
                                    // Clear in-memory tracker first so reads
                                    // are
                                    // unblocked as soon as the batch commits.
                                    // Harmless no-op on nodes that were never
                                    // quarantined for this partition.
                                    self.quarantine.clear(&partition);
                                    // Remove every reporting node's marker for
                                    // this partition — the operator clears the
                                    // partition cluster-wide, not just the node
                                    // they happened to connect to.
                                    let scan_prefix =
                                        format!("{QUARANTINE_META_PREFIX}{partition}:");
                                    let keys_to_remove: Vec<Vec<u8>> = self
                                        .meta
                                        .prefix(scan_prefix.as_bytes())
                                        .filter_map(|item| item.into_inner().ok())
                                        .map(|(k, _)| k.to_vec())
                                        .collect();
                                    for key in &keys_to_remove {
                                        batch.remove(&self.meta, key.as_slice());
                                    }
                                    tracing::info!(partition, "quarantine cleared by operator");
                                }
                                MutationInner::Quarantine {
                                    node_id: reporting_node,
                                    partition,
                                } => {
                                    // Applied uniformly on every node. Only
                                    // the reporting node updates its own
                                    // blocking in-memory state; other nodes
                                    // persist the record for audit
                                    // visibility only (ADR 0016-v2 §10
                                    // invariant 5).
                                    let key = quarantine_meta_key(&partition, reporting_node);
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    batch.insert(&self.meta, key.as_bytes(), now.to_be_bytes());
                                    if reporting_node == self.node_id {
                                        self.quarantine.force_quarantine(&partition);
                                    }
                                    tracing::info!(
                                        partition,
                                        reporting_node,
                                        "quarantine committed via Raft"
                                    );
                                }
                                MutationInner::InstallDek {
                                    wrapped_dek,
                                    dek_version,
                                    is_emergency,
                                } => {
                                    let raw_dek = self
                                        .kek
                                        .unwrap_dek(&wrapped_dek)
                                        .map_err(|e| io::Error::other(e.to_string()))?;
                                    let locked_dek = LockedKey::from_raw(*raw_dek);
                                    let new_epoch = Arc::new(
                                        DekEpoch::from_raw(locked_dek, dek_version)
                                            .map_err(|e| io::Error::other(e.to_string()))?,
                                    );
                                    // Persist new DEK: [version_u32_BE; 4] ++
                                    // wrapped_bytes.
                                    let mut persisted = dek_version.to_be_bytes().to_vec();
                                    persisted.extend_from_slice(&wrapped_dek);
                                    batch.insert(&self.meta, META_DEK_CURRENT, persisted);
                                    let old_version = {
                                        let g = self.dek.read().unwrap_or_else(|p| p.into_inner());
                                        g.version
                                    };
                                    // Only persist retired DEK if not emergency
                                    // (emergency
                                    // revokes).
                                    if !is_emergency {
                                        let retired_key =
                                            format!("{DEK_RETIRED_PREFIX}{old_version}");
                                        match self.meta.get(META_DEK_CURRENT) {
                                            Ok(Some(cur)) if cur.len() > 4 => {
                                                batch.insert(
                                                    &self.meta,
                                                    retired_key.as_bytes(),
                                                    &cur[4..],
                                                );
                                            }
                                            _ => {
                                                tracing::warn!(
                                                    old_version,
                                                    "could not read current DEK bytes for \
                                                     retirement record; pre-rotation ciphertext \
                                                     may be unreadable after restart"
                                                );
                                            }
                                        }
                                    } else {
                                        // Emergency rotation: durably record
                                        // the revoked
                                        // marker in the same atomic batch as
                                        // the DEK swap,
                                        // so containment survives a restart
                                        // (ADR 0016-v2
                                        // §6.2 step 2). This timestamp-only
                                        // marker is
                                        // permanent and is never removed.
                                        let revoked_key =
                                            format!("{DEK_REVOKED_PREFIX}{old_version}");
                                        let now = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();
                                        batch.insert(
                                            &self.meta,
                                            revoked_key.as_bytes(),
                                            now.to_be_bytes(),
                                        );

                                        // Also stage the old epoch's wrapped
                                        // bytes under a
                                        // *separate*, temporary prefix so the
                                        // re-encryption
                                        // sweep this rotation still requires
                                        // (ADR §6.2 step
                                        // 4) survives a restart before it
                                        //    completes.
                                        // `reencrypt_pending` deletes this
                                        // entry the moment
                                        // the sweep confirms every record has
                                        // migrated and
                                        // no log entry still references it —
                                        // only then is
                                        // the compromised key genuinely
                                        // discarded (step 5).
                                        let revoked_pending_key =
                                            format!("{DEK_REVOKED_PENDING_PREFIX}{old_version}");
                                        match self.meta.get(META_DEK_CURRENT) {
                                            Ok(Some(cur)) if cur.len() > 4 => {
                                                batch.insert(
                                                    &self.meta,
                                                    revoked_pending_key.as_bytes(),
                                                    &cur[4..],
                                                );
                                            }
                                            _ => {
                                                tracing::error!(
                                                    old_version,
                                                    "SECURITY: could not read current DEK \
                                                     bytes to stage emergency re-encryption; \
                                                     records under the revoked epoch may \
                                                     become permanently unreadable"
                                                );
                                            }
                                        }
                                    }
                                    pending_dek_swap = Some((new_epoch, is_emergency));
                                    tracing::info!(
                                        old_version,
                                        new_version = dek_version,
                                        is_emergency,
                                        "DEK rotation: epoch swap queued"
                                    );
                                }
                                MutationInner::CreatePendingRotation {
                                    rotation_id,
                                    wrapped_dek,
                                    dek_version,
                                    expires_at,
                                    initiator,
                                } => {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    // Remove any pre-existing expired entries
                                    // first.
                                    let mut pending = self
                                        .pending_rotations
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner());
                                    pending.retain(|_, v| v.expires_at > now);

                                    if !pending.is_empty() {
                                        violations.push(Violation {
                                            r#type: "CONFLICT".to_string(),
                                            subject: rotation_id.clone(),
                                            description: "another emergency rotation is already \
                                                          pending; confirm or wait for it to expire"
                                                .to_string(),
                                        });
                                    } else {
                                        let entry = PendingRotation {
                                            rotation_id: rotation_id.clone(),
                                            wrapped_dek: wrapped_dek.clone(),
                                            dek_version,
                                            expires_at,
                                            initiator: initiator.clone(),
                                        };
                                        let serialised = rmp_serde::to_vec(&entry)
                                            .map_err(|e| io::Error::other(e.to_string()))?;
                                        let meta_key =
                                            format!("{PENDING_ROTATION_PREFIX}{rotation_id}");
                                        batch.insert(&self.meta, meta_key.as_bytes(), serialised);
                                        // Not inserted into `pending` yet —
                                        // deferred
                                        // until the whole transaction's `batch`
                                        // actually commits (see
                                        // `pending_rotation_mutation` above).
                                        pending_rotation_mutation =
                                            Some(PendingRotationMutation::Insert(
                                                rotation_id.clone(),
                                                entry,
                                            ));
                                        tracing::info!(
                                            rotation_id,
                                            dek_version,
                                            initiator,
                                            expires_at,
                                            "emergency DEK rotation staged; awaiting confirmation"
                                        );
                                    }
                                }
                                MutationInner::ConfirmPendingRotation {
                                    rotation_id,
                                    confirmer,
                                } => {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    // Peek rather than remove (GitHub #1297
                                    // item 4):
                                    // the old code removed the entry from the
                                    // in-memory map up front, but on the
                                    // NOT_FOUND/EXPIRED violation branches
                                    // below
                                    // the surrounding `batch` is never
                                    // committed
                                    // (nothing here ever put it back for those
                                    // two cases), leaving the in-memory map and
                                    // the Fjall `meta` entry disagreeing until
                                    // restart. Only the genuine success arm
                                    // below
                                    // now removes it.
                                    let entry = self
                                        .pending_rotations
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner())
                                        .get(&rotation_id)
                                        .cloned();
                                    match entry {
                                        None => {
                                            violations.push(Violation {
                                                r#type: "NOT_FOUND".to_string(),
                                                subject: rotation_id.clone(),
                                                description: format!(
                                                    "no pending emergency rotation with id \
                                                     {rotation_id}"
                                                ),
                                            });
                                        }
                                        Some(ref e) if e.expires_at <= now => {
                                            violations.push(Violation {
                                                r#type: "EXPIRED".to_string(),
                                                subject: rotation_id.clone(),
                                                description: format!(
                                                    "pending rotation {rotation_id} expired at \
                                                     {} ({}s ago)",
                                                    e.expires_at,
                                                    now.saturating_sub(e.expires_at)
                                                ),
                                            });
                                        }
                                        Some(ref e) if e.initiator == confirmer => {
                                            violations.push(Violation {
                                                r#type: "UNAUTHORIZED".to_string(),
                                                subject: rotation_id.clone(),
                                                description: "the confirming operator must be \
                                                              different from the initiator \
                                                              (dual-control requirement)"
                                                    .to_string(),
                                            });
                                        }
                                        Some(entry) => {
                                            // Dual-control satisfied — execute
                                            // DEK install.
                                            // Removal from `pending` is
                                            // deferred
                                            // until the batch actually commits
                                            // (see `pending_rotation_mutation`).
                                            pending_rotation_mutation =
                                                Some(PendingRotationMutation::Remove(
                                                    rotation_id.clone(),
                                                ));
                                            let meta_key =
                                                format!("{PENDING_ROTATION_PREFIX}{rotation_id}");
                                            batch.remove(&self.meta, meta_key.as_bytes());

                                            let raw_dek =
                                                self.kek
                                                    .unwrap_dek(&entry.wrapped_dek)
                                                    .map_err(|e| io::Error::other(e.to_string()))?;
                                            let locked_dek = LockedKey::from_raw(*raw_dek);
                                            let new_epoch = Arc::new(
                                                DekEpoch::from_raw(locked_dek, entry.dek_version)
                                                    .map_err(|e| io::Error::other(e.to_string()))?,
                                            );
                                            let mut persisted =
                                                entry.dek_version.to_be_bytes().to_vec();
                                            persisted.extend_from_slice(&entry.wrapped_dek);
                                            batch.insert(&self.meta, META_DEK_CURRENT, persisted);
                                            let old_version = {
                                                let g = self
                                                    .dek
                                                    .read()
                                                    .unwrap_or_else(|p| p.into_inner());
                                                g.version
                                            };

                                            // Dual-control-confirmed emergency
                                            // rotation:
                                            // same containment +
                                            // staged-re-encryption
                                            // bookkeeping as `InstallDek`'s
                                            // emergency
                                            // branch (ADR 0016-v2 §6.2 steps 2,
                                            // 4) — this
                                            // path used to skip both durable
                                            // writes
                                            // entirely, silently losing
                                            // revocation status
                                            // and the re-encryption key on
                                            // restart
                                            // (GitHub #1299).
                                            let revoked_key =
                                                format!("{DEK_REVOKED_PREFIX}{old_version}");
                                            let now = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_secs();
                                            batch.insert(
                                                &self.meta,
                                                revoked_key.as_bytes(),
                                                now.to_be_bytes(),
                                            );
                                            let revoked_pending_key = format!(
                                                "{DEK_REVOKED_PENDING_PREFIX}{old_version}"
                                            );
                                            match self.meta.get(META_DEK_CURRENT) {
                                                Ok(Some(cur)) if cur.len() > 4 => {
                                                    batch.insert(
                                                        &self.meta,
                                                        revoked_pending_key.as_bytes(),
                                                        &cur[4..],
                                                    );
                                                }
                                                _ => {
                                                    tracing::error!(
                                                        old_version,
                                                        rotation_id,
                                                        "SECURITY: could not read current \
                                                         DEK bytes to stage emergency \
                                                         re-encryption; records under the \
                                                         revoked epoch may become \
                                                         permanently unreadable"
                                                    );
                                                }
                                            }

                                            pending_dek_swap = Some((new_epoch, true));
                                            tracing::warn!(
                                                rotation_id,
                                                old_version,
                                                new_version = entry.dek_version,
                                                initiator = entry.initiator,
                                                confirmer,
                                                "SECURITY: emergency DEK rotation confirmed \
                                                 (dual-control); epoch swap queued"
                                            );
                                        }
                                    }
                                }
                                MutationInner::AbortPendingRotation { rotation_id } => {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    let mut pending = self
                                        .pending_rotations
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner());
                                    // Defensive re-check: only remove if still
                                    // present and
                                    // actually expired. A ConfirmRotateDek may
                                    // have raced
                                    // ahead of the sweeper and already resolved
                                    // this entry,
                                    // or the sweeper's read may have been stale
                                    // — either
                                    // way this is a silent no-op, not a
                                    // violation.
                                    if let Some(entry) = pending.get(&rotation_id)
                                        && entry.expires_at <= now
                                    {
                                        let removed = pending.remove(&rotation_id);
                                        drop(pending);
                                        if let Some(entry) = removed {
                                            let meta_key =
                                                format!("{PENDING_ROTATION_PREFIX}{rotation_id}");
                                            batch.remove(&self.meta, meta_key.as_bytes());
                                            tracing::warn!(
                                                rotation_id,
                                                initiator = entry.initiator,
                                                expires_at = entry.expires_at,
                                                "SECURITY: emergency DEK rotation confirmation \
                                                 window expired with no confirmation — \
                                                 automatically aborted (ADR 0016-v2 §6.2 step 1)"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        has_violations = !violations.is_empty();
                        (None, violations)
                    }
                }
            } else if let Some(mem) = entry.membership {
                last_membership = Some(StoredMembershipOf::<TypeConfig>::new(
                    Some(last_applied_log),
                    mem.try_into()?,
                ));
                (None, vec![])
            } else {
                (None, vec![])
            };

            if !has_violations {
                batch
                    .commit()
                    .map_err(|e| io::Error::other(e.to_string()))?;

                match pending_rotation_mutation {
                    Some(PendingRotationMutation::Insert(id, entry)) => {
                        self.pending_rotations
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .insert(id, entry);
                    }
                    Some(PendingRotationMutation::Remove(id)) => {
                        self.pending_rotations
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&id);
                    }
                    None => {}
                }

                // Swap the active DEK epoch after a successful InstallDek
                // commit.
                if let Some((new_epoch, is_emergency_rotation)) = pending_dek_swap {
                    // Audit key follows the DEK epoch (ADR 0016-v2 §3.1):
                    // derive it before `new_epoch` moves into the swap.
                    let new_version = new_epoch.version;
                    let new_audit_key = new_epoch.derive_audit_key(self.node_id);
                    let old_epoch = {
                        let mut guard = self.dek.write().unwrap_or_else(|p| p.into_inner());
                        std::mem::replace(&mut *guard, new_epoch)
                    };
                    if is_emergency_rotation {
                        // Emergency: old DEK is revoked, not retired — but it
                        // must still go through the standard re-encryption
                        // sweep before its key material is discarded (ADR
                        // 0016-v2 §6.2 step 4 runs *before* step 5). Dropping
                        // it here immediately, as this used to do, silently
                        // and permanently loses every record, in-flight log
                        // entry, and local snapshot still under this epoch
                        // (GitHub #1299). `revoked_deks` still marks the
                        // version as compromised so it is never handed to a
                        // joining node (`FetchDek`) or reused for anything
                        // new; `finalize_if_revoked` (called from
                        // `reencrypt_pending`) removes it from `old_deks` —
                        // the actual, final discard — only once the sweep
                        // confirms nothing needs the key anymore.
                        let mut revoked =
                            self.revoked_deks.lock().unwrap_or_else(|p| p.into_inner());
                        if revoked.len() >= MAX_REVOKED_DEKS {
                            tracing::error!(
                                capacity = MAX_REVOKED_DEKS,
                                "revoked_deks set is full; this node has had an extraordinary \
                                 number of emergency rotations — operator review required"
                            );
                        }
                        revoked.insert(old_epoch.version);
                        drop(revoked);
                        tracing::warn!(
                            version = old_epoch.version,
                            "SECURITY: emergency DEK rotation — old DEK version revoked; \
                             re-encryption sweep starting before the key is discarded \
                             (ADR 0016-v2 §6.2 step 4)"
                        );
                    }
                    // Register old epoch for state/log read fallback during
                    // re-encryption -- for an emergency rotation this is
                    // temporary (see comment above); for a normal rotation
                    // it is kept forever for backup decryption (ADR §7).
                    self.old_deks
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(old_epoch.version, old_epoch.clone());
                    // Signal background re-encryption task (non-fatal on
                    // channel full).
                    let _ = self.reencrypt_tx.try_send(old_epoch);
                    tracing::info!("DEK epoch swapped");
                    // Every node audits the apply-side outcome and switches
                    // its signing key to the new epoch.
                    if let Some(audit) = self.audit.get() {
                        match new_audit_key {
                            Ok(key) => audit.rotate_key(new_version, key),
                            Err(e) => tracing::error!(
                                error = %e,
                                version = new_version,
                                "AUDIT: failed to derive audit key for new DEK epoch; \
                                 records will be signed with the previous epoch key"
                            ),
                        }
                        audit.emit(crate::audit::AuditRecord::now(
                            "DEK_INSTALLED",
                            "raft-apply",
                            self.node_id,
                            new_version,
                            serde_json::json!({ "emergency": is_emergency_rotation }),
                        ));
                    }
                }
            }

            // Not fsynced here (see the comment on `pending_responses`
            // above) — folded into the single `persist(SyncAll)` below,
            // covering every entry in this apply() call.
            self.meta
                .insert(
                    KEY_LAST_APPLIED_LOG,
                    rmp_serde::to_vec(&last_applied_log)
                        .map_err(|e| io::Error::other(e.to_string()))?,
                )
                .map_err(|e| io::Error::other(e.to_string()))?;

            self.raft_prometheus_metrics
                .apply_duration_seconds
                .record(apply_start.elapsed().as_secs_f64());

            if let Some(responder) = responder {
                pending_responses.push((
                    responder,
                    crate::ZeroizingResponse {
                        value: response.0.map(zeroize::Zeroizing::new),
                        violations: response.1,
                    },
                ));
            }
        }

        let mut meta_batch = self.db.batch();
        if let Some(val) = last_membership {
            meta_batch.insert(
                &self.meta,
                KEY_LAST_MEMBERSHIP,
                rmp_serde::to_vec(&val).map_err(|e| io::Error::other(e.to_string()))?,
            );
        }
        meta_batch
            .commit()
            .map_err(|e| io::Error::other(e.to_string()))?;

        self.db
            .persist(PersistMode::SyncAll)
            .map_err(|e| io::Error::other(e.to_string()))?;

        // Every entry in this apply() call is now durable — safe to
        // notify callers.
        for (responder, response) in pending_responses {
            responder.send(response);
        }
        Ok(())
    }
}
