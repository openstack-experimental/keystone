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

use openstack_keystone_storage_crypto::EnvKek;

use super::*;

fn test_epoch(seed: u8, version: u32) -> Arc<DekEpoch> {
    Arc::new(DekEpoch::from_raw(LockedKey::from_raw([seed; 32]), version).expect("epoch"))
}

/// Builds a `FjallStateMachine` with directly controllable `dek` /
/// `old_deks` state, so tests can simulate a rotation transition without
/// going through the full Raft apply path.
fn make_sm(current: Arc<DekEpoch>) -> (FjallStateMachine, tempfile::TempDir) {
    let td = tempfile::TempDir::new().expect("tempdir");
    let db = Arc::new(Database::builder(td.path()).open().expect("open db"));
    let kek: Arc<dyn KekProvider> = Arc::new(EnvKek::from_bytes([0x42u8; 32]));
    let (reencrypt_tx, reencrypt_rx) = tokio::sync::mpsc::channel(1);
    drop(reencrypt_rx);
    let (quarantine_tx, quarantine_rx) = tokio::sync::mpsc::channel(1);
    drop(quarantine_rx);

    let sm = FjallStateMachine::new(
        db,
        td.path().join("snapshots"),
        1, // node_id
        Arc::new(RwLock::new(current)),
        Arc::new(Mutex::new(BTreeMap::new())),
        Arc::new(Mutex::new(HashSet::new())),
        kek,
        reencrypt_tx,
        quarantine_tx,
        Arc::new(Mutex::new(HashMap::new())),
    )
    .expect("construct state machine");
    (sm, td)
}

#[test]
fn decrypt_with_matching_current_version_succeeds() {
    let epoch = test_epoch(0x01, 1);
    let (sm, _td) = make_sm(epoch);

    let ks = sm.data().clone();
    let (ciphertext, version) = sm
        .encrypt_and_store(&ks, b"k1", b"data", DataTier::Internal as u8, b"hello")
        .expect("encrypt");
    assert_eq!(version, 1);

    let plaintext = sm
        .decrypt_state(
            &ciphertext,
            DataTier::Internal as u8,
            b"data",
            b"k1",
            Some(version),
        )
        .expect("decrypt with correct hint");
    assert_eq!(plaintext, b"hello");
}

#[test]
fn decrypt_with_retired_epoch_hint_succeeds_without_probing() {
    let old_epoch = test_epoch(0x02, 1);
    let (sm, _td) = make_sm(old_epoch.clone());

    let ks = sm.data().clone();
    let (ciphertext, old_version) = sm
        .encrypt_and_store(&ks, b"k2", b"data", DataTier::Internal as u8, b"hello")
        .expect("encrypt under epoch 1");
    assert_eq!(old_version, 1);

    // Simulate a rotation: swap in a new current epoch, retire the old one.
    let new_epoch = test_epoch(0x03, 2);
    *sm.dek.write().unwrap() = new_epoch;
    sm.old_deks.lock().unwrap().insert(1, old_epoch);

    // Old records still decrypt via the exact retired epoch named by hint.
    let plaintext = sm
        .decrypt_state(
            &ciphertext,
            DataTier::Internal as u8,
            b"data",
            b"k2",
            Some(old_version),
        )
        .expect("decrypt via retired epoch hint");
    assert_eq!(plaintext, b"hello");
}

#[test]
fn decrypt_with_wrong_version_hint_fails_without_probing() {
    let epoch1 = test_epoch(0x04, 1);
    let (sm, _td) = make_sm(epoch1.clone());

    let ks = sm.data().clone();
    let (ciphertext, _version) = sm
        .encrypt_and_store(&ks, b"k3", b"data", DataTier::Internal as u8, b"hello")
        .expect("encrypt under epoch 1");

    // Rotate so epoch 1 becomes retired (and decryptable, if probed).
    let epoch2 = test_epoch(0x05, 2);
    *sm.dek.write().unwrap() = epoch2;
    sm.old_deks.lock().unwrap().insert(1, epoch1);

    // A hint naming a version that exists in neither current nor
    // old_deks must fail outright — never silently fall back to
    // probing epoch 1, even though epoch 1 would actually decrypt it
    // (ADR 0016-v2 §6 step 6).
    let err = sm
        .decrypt_state(
            &ciphertext,
            DataTier::Internal as u8,
            b"data",
            b"k3",
            Some(99),
        )
        .expect_err("unknown dek_version hint must not silently probe other keys");
    assert!(!matches!(err, StoreError::Quarantined(_)));
}

/// `retired_deks_wrapped`/`install_fetched_retired_dek` round-trip:
/// records a leader retires on rotation must still be decryptable by a
/// node that only adopted them via `FetchDek` (GitHub issue #1298) —
/// not just records under the current epoch.
#[test]
fn fetch_and_install_retired_dek_round_trips() {
    let kek: Arc<dyn KekProvider> = Arc::new(EnvKek::from_bytes([0x42u8; 32]));

    // --- "Leader" side: encrypt a record under epoch 1, then rotate to
    //     epoch 2 and persist epoch 1's wrapped bytes as retired, the
    //     same way `InstallDek`'s apply() does.
    let raw_v1 = [0xAAu8; 32];
    let wrapped_v1 = kek.wrap_dek(&raw_v1).expect("wrap v1");
    let epoch_v1 =
        Arc::new(DekEpoch::from_raw(LockedKey::from_raw(raw_v1), 1).expect("construct epoch 1"));
    let (leader_sm, _td1) = make_sm(epoch_v1);

    let ks = leader_sm.data().clone();
    let (ciphertext, version) = leader_sm
        .encrypt_and_store(&ks, b"k1", b"data", DataTier::Internal as u8, b"hello")
        .expect("encrypt under epoch 1");
    assert_eq!(version, 1);

    let epoch_v2 = test_epoch(0x99, 2);
    *leader_sm.dek.write().unwrap() = epoch_v2;
    leader_sm
        .meta()
        .insert(format!("{DEK_RETIRED_PREFIX}1"), &wrapped_v1)
        .expect("persist retired epoch 1");

    let retired = leader_sm.retired_deks_wrapped().expect("read retired DEKs");
    assert_eq!(retired, vec![(1, wrapped_v1.clone())]);

    // --- "Joining node" side: starts with an unrelated current epoch
    //     and no retired epochs at all, then adopts epoch 1 purely via
    //     `install_fetched_retired_dek` (as `join_cluster` would).
    let (joiner_sm, _td2) = make_sm(test_epoch(0x11, 2));
    assert!(joiner_sm.old_deks.lock().unwrap().is_empty());

    joiner_sm
        .install_fetched_retired_dek(1, &wrapped_v1)
        .expect("install fetched retired DEK");
    assert!(joiner_sm.old_deks.lock().unwrap().contains_key(&1));

    // The joining node must decrypt the leader's epoch-1 ciphertext
    // using only what `FetchDek` handed it -- the exact scenario a DEK
    // rotation's still-in-flight background re-encryption sweep leaves
    // behind.
    let plaintext = joiner_sm
        .decrypt_state(
            &ciphertext,
            DataTier::Internal as u8,
            b"data",
            b"k1",
            Some(1),
        )
        .expect("joining node decrypts leader's retired-epoch record");
    assert_eq!(plaintext, b"hello");
}

#[test]
fn decrypt_legacy_none_hint_still_probes_retired_epochs() {
    let epoch1 = test_epoch(0x06, 1);
    let (sm, _td) = make_sm(epoch1.clone());

    let ks = sm.data().clone();
    let (ciphertext, _version) = sm
        .encrypt_and_store(&ks, b"k4", b"data", DataTier::Internal as u8, b"hello")
        .expect("encrypt under epoch 1");

    let epoch2 = test_epoch(0x07, 2);
    *sm.dek.write().unwrap() = epoch2;
    sm.old_deks.lock().unwrap().insert(1, epoch1);

    // Legacy records (no dek_version recorded) still fall back to
    // try-current-then-probe-retired for backward compatibility.
    let plaintext = sm
        .decrypt_state(&ciphertext, DataTier::Internal as u8, b"data", b"k4", None)
        .expect("legacy probe path should still find the retired epoch");
    assert_eq!(plaintext, b"hello");
}

/// Regression test for GitHub #1295 (second defect): a record still
/// pending re-encryption under a retired epoch must have its per-record
/// nonce version continued from where it actually was, not reset to 0
/// by blindly decrypting the existing ciphertext with the *current*
/// epoch (which always fails GCM verification for such a record) and
/// falling back to `unwrap_or(0)`.
#[test]
fn encrypt_and_store_continues_version_across_retired_epoch_instead_of_resetting() {
    let old_epoch = test_epoch(0x30, 1);
    let (sm, _td) = make_sm(old_epoch.clone());

    let ks = sm.data().clone();
    let (ciphertext1, dek_version1) = sm
        .encrypt_and_store(&ks, b"k1", b"data", DataTier::Internal as u8, b"hello")
        .expect("first write under epoch 1");
    assert_eq!(dek_version1, 1);
    ks.insert(b"k1", ciphertext1).expect("insert ciphertext");
    let mut metadata = Metadata::new();
    metadata.dek_version = Some(dek_version1);
    sm.meta()
        .insert(
            meta_key("data", b"k1"),
            metadata.pack().expect("pack metadata"),
        )
        .expect("insert metadata");

    // Rotate: k1's record is now under a retired epoch, exactly as it
    // would be before a background re-encryption sweep reaches it.
    let new_epoch = test_epoch(0x31, 2);
    *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = new_epoch.clone();
    sm.old_deks
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(old_epoch.version, old_epoch.clone());

    // A second write to the same still-pending key must look up its
    // real epoch (1) via `Metadata::dek_version` rather than guessing
    // with the new current epoch (2).
    let (ciphertext2, dek_version2) = sm
        .encrypt_and_store(&ks, b"k1", b"data", DataTier::Internal as u8, b"world")
        .expect("second write must not error out");
    assert_eq!(dek_version2, 2);

    let (plaintext2, next_version) = state_decrypt(
        new_epoch.state_dek(),
        &ciphertext2,
        DataTier::Internal as u8,
        b"data",
        b"k1",
    )
    .expect("decrypt second write under the new current epoch");
    assert_eq!(&*plaintext2, b"world");
    assert_eq!(
        next_version, 2,
        "nonce version must continue from the record's real prior version (0 -> 1), \
         not reset to 0 by decrypting with the wrong (current) epoch"
    );
}

/// Regression test for GitHub #1295 (second defect): a genuinely
/// tampered/corrupted existing record must fail the write with a
/// `StoreError::Crypto` and count toward quarantine, not be silently
/// overwritten as if it were merely pending re-encryption under an
/// older epoch.
#[test]
fn encrypt_and_store_quarantines_instead_of_silently_overwriting_tampered_record() {
    let epoch = test_epoch(0x34, 1);
    let (sm, _td) = make_sm(epoch.clone());

    let ks = sm.data().clone();
    let (mut ciphertext, dek_version) = sm
        .encrypt_and_store(&ks, b"k1", b"data", DataTier::Internal as u8, b"hello")
        .expect("initial encrypt");
    // Flip a ciphertext byte (right after the 12-byte nonce prefix) so
    // the GCM tag no longer verifies -- simulates tampering, as
    // opposed to the record merely being under a different epoch.
    ciphertext[12] ^= 0xFF;
    ks.insert(b"k1", ciphertext.clone())
        .expect("insert tampered ciphertext");
    let mut metadata = Metadata::new();
    metadata.dek_version = Some(dek_version);
    sm.meta()
        .insert(
            meta_key("data", b"k1"),
            metadata.pack().expect("pack metadata"),
        )
        .expect("insert metadata");

    // QUARANTINE_THRESHOLD (3) identical failures within the sliding
    // window trip quarantine; each one must reject the write instead of
    // silently overwriting the tampered record.
    for attempt in 1..=QUARANTINE_THRESHOLD {
        let err = sm
            .encrypt_and_store(&ks, b"k1", b"data", DataTier::Internal as u8, b"new-value")
            .expect_err(
                "a corrupted existing record must not be silently overwritten with version 0",
            );
        assert!(
            matches!(
                err,
                StoreError::Crypto {
                    source: openstack_keystone_storage_crypto::CryptoError::AesDecrypt
                }
            ),
            "attempt {attempt}: expected a GCM tag-verification failure, got: {err:?}"
        );
    }

    // The ciphertext on disk must be untouched -- every write must have
    // been rejected before ever reaching the batch commit.
    let still_stored = ks.get(b"k1").expect("get data").expect("present");
    assert_eq!(still_stored.as_ref(), ciphertext.as_slice());

    assert!(
        sm.is_quarantined("data"),
        "repeated GCM failures against the same partition must quarantine it"
    );

    // Quarantine and GCM failures are visible to monitoring (GitHub #1306).
    let status = sm.node_status();
    assert_eq!(status.quarantined_partitions, vec!["data".to_string()]);
    assert_eq!(status.dek_version, 1);
    assert_eq!(
        sm.raft_prometheus_metrics().gcm_failures_total.get(),
        QUARANTINE_THRESHOLD as u64
    );
}

/// A hint naming an epoch that is genuinely gone (not in `old_deks`)
/// *and* known to have been emergency-revoked (ADR 0016-v2 §6.2) must
/// fail with a clean `RevokedDek` error, not be miscategorized as
/// corruption and trip the quarantine threshold (GitHub #1299). By the
/// time this can happen for a real record, `finalize_if_revoked` has
/// already confirmed nothing needs the key anymore.
#[test]
fn decrypt_with_revoked_and_discarded_epoch_returns_clean_error_not_quarantine() {
    let epoch = test_epoch(0x08, 2);
    let (sm, _td) = make_sm(epoch);

    sm.revoked_deks.lock().unwrap().insert(1);

    let err = sm
        .decrypt_state(
            b"irrelevant-ciphertext",
            DataTier::Internal as u8,
            b"data",
            b"k1",
            Some(1),
        )
        .expect_err("a revoked, fully-discarded epoch must not decrypt");
    assert!(
        matches!(
            err,
            StoreError::Crypto {
                source: openstack_keystone_storage_crypto::CryptoError::RevokedDek { version: 1 }
            }
        ),
        "expected a clean RevokedDek error, got: {err:?}"
    );
}

/// A DEK swap applied before the audit forwarder is attached must not leave
/// the forwarder signing with a stale epoch key (GitHub #1300).
#[tokio::test]
async fn attaching_audit_forwarder_syncs_key_to_current_epoch() {
    let (sm, td) = make_sm(test_epoch(0x06, 1));
    let epoch2 = test_epoch(0x07, 2);
    // Forwarder built from epoch 1, then the swap lands before attach.
    let epoch1_key = test_epoch(0x06, 1).derive_audit_key(1).expect("key");
    let (fwd, _task) = crate::audit::AuditForwarder::spawn(
        1,
        epoch1_key,
        crate::audit::AuditSpoolConfig {
            dir: td.path().join("audit"),
            node_id: 1,
            max_bytes: 1 << 20,
        },
    )
    .expect("spawn");
    *sm.dek.write().unwrap() = epoch2.clone();

    sm.set_audit_forwarder(fwd.clone());
    fwd.emit(crate::audit::AuditRecord::now(
        "T",
        "op",
        1,
        2,
        serde_json::json!({}),
    ));

    let spool = td.path().join("audit").join("raft-audit-1.jsonl");
    let mut line = String::new();
    for _ in 0..100 {
        line = std::fs::read_to_string(&spool).unwrap_or_default();
        if !line.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(line.contains(r#""key_version":2"#), "got: {line}");
    let (record, rest) = line
        .strip_prefix(r#"{"record":"#)
        .and_then(|l| l.split_once(r#","key_version":"#))
        .expect("framing");
    let hmac = rest.split_once(r#","hmac":""#).expect("framing").1;
    let mac: String = epoch2
        .derive_audit_key(1)
        .expect("key")
        .sign(record.as_bytes())
        .expect("sign")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(hmac.trim().trim_end_matches(r#""}"#), mac);
}
