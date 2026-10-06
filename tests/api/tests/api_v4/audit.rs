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
//! Live CADF spool assertions (issue #1325, the last open items).
//!
//! Runs against the live server started by `tools/start-api.sh` (the `api`
//! nextest profile), performs real actions, and then reads the audit spool
//! that server writes:
//!
//! 1. Password login as admin — a perimeter record on the best-effort channel
//!    (`POST /v3/auth/tokens` is an authentication surface, so the completion
//!    middleware records it even though no provider operation runs).
//! 2. User create + delete — provider records on the fail-closed channel: one
//!    `pending` line and one terminal line per operation
//!    (`crates/core/src/identity/service.rs`, `audited_op!`).
//! 3. API key create + revoke — provider records; the revoke handler
//!    (`crates/keystone/src/api/v4/api_key/revoke.rs`) has no audit call of its
//!    own, the record is written in the provider
//!    (`crates/core/src/api_key/service.rs`) via `audited_if_ctx!`, which only
//!    audits when an execution context is present, so a mocked handler test
//!    cannot observe it. A live request is the only way to cover it.
//!
//! The spool is written asynchronously and is not fsynced per perimeter
//! record, so the expected lines are polled for. The test skips (rather
//! than fails) when the spool directory is absent, i.e. when run without
//! the `api` profile.
//!
//! Every line of the live spool — not only the ones this test triggered —
//! is parsed and its HMAC-SHA256 signature is verified against the per-node
//! key derived from the keyring file, exactly as a SIEM would verify it (see
//! `crates/cadf/tests/hmac_vectors.rs` for the reference procedure).
//!
//! `tools/start-api.sh` writes `[audit] spool_dir =
//! /tmp/nextest/keystone/audit` and `node_id = api-test-node` and leaves
//! `hmac_kek_file` unset, so the keyring sits at the legacy default
//! `<spool_dir>/hmac-key.bin` (see `AuditConfig::hmac_kek_path`).
//! `AUDIT_SPOOL_DIR` overrides the spool directory for manual runs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cadf::{
    AuditDispatcher, CadfEvent, CadfEventPayload, HmacKeyring, Initiator, Observer,
    ServiceIdentity, Target, derive_audit_hmac_key,
};
use eyre::{Result, bail, eyre};
use openstack_sdk::AsyncOpenStack;
use uuid::Uuid;

use openstack_keystone_api_types::v3::user::{UserCreate, UserCreateBuilder};

use test_api::api_key::{create_api_key, revoke_api_key, sample_api_key_create};
use test_api::common::get_system_scope_session;
use test_api::identity::user::{UserListRequest, create_user, delete_user, list_users};

/// The domain every fixture in this test lives in.
const DOMAIN: &str = "default";
/// The `[audit] node_id` written by `tools/start-api.sh`.
const NODE_ID: &str = "api-test-node";
/// The fixed `STATE_DIR` of `tools/start-api.sh`.
const DEFAULT_SPOOL_DIR: &str = "/tmp/nextest/keystone/audit";
/// The service identity the live server signs with (`AUDIT_SERVICE` in
/// `crates/keystone`); it drives the HKDF label of the node key.
const AUDIT_SERVICE: ServiceIdentity = ServiceIdentity::new("keystone");
/// `EventPayload::User` target (`crates/core/src/cadf_hook.rs`).
const USER_TYPE_URI: &str = "data/security/identity/user";
/// `EventPayload::ApiKey` target (`crates/core/src/cadf_hook.rs`).
const API_KEY_TYPE_URI: &str = "data/security/identity/api-key";
/// Perimeter authentication target (`crates/keystone/src/audit.rs`).
const AUTH_TYPE_URI: &str = "service/security/keystone/auth";
/// Records land in the spool asynchronously; poll this often.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How long to wait for the expected lines before failing.
const SPOOL_TIMEOUT: Duration = Duration::from_secs(15);

/// The spool directory to read, or `None` when this run has no live server
/// and the test must skip.
fn spool_dir() -> Result<Option<PathBuf>> {
    match std::env::var("AUDIT_SPOOL_DIR") {
        Ok(dir) => {
            let path = PathBuf::from(&dir);
            if !path.is_dir() {
                bail!("AUDIT_SPOOL_DIR={dir} is not a directory");
            }
            Ok(Some(path))
        }
        Err(_) => {
            let path = PathBuf::from(DEFAULT_SPOOL_DIR);
            Ok(path.is_dir().then_some(path))
        }
    }
}

/// The per-node live spool file: `audit-spool-{node_id}.jsonl`.
fn live_spool_file(spool_dir: &Path) -> PathBuf {
    spool_dir.join(format!("audit-spool-{NODE_ID}.jsonl"))
}

/// Load the HMAC keyring the live server signs with.
///
/// `hmac_kek_file` is unset in `tools/start-api.sh`, so the keyring is at
/// the legacy location `<spool_dir>/hmac-key.bin`; accept any `hmac-key*`
/// file in the directory so an operator-supplied name keeps working.
fn load_keyring(spool_dir: &Path) -> Result<HmacKeyring> {
    let candidates = std::fs::read_dir(spool_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("hmac-key"))
        })
        .collect::<Vec<_>>();
    for path in &candidates {
        if let Some(keyring) = HmacKeyring::load(path)? {
            return Ok(keyring);
        }
    }
    bail!(
        "no HMAC keyring file (hmac-key*) found in {}",
        spool_dir.display()
    )
}

/// Read the live spool and parse every complete line.
///
/// A torn final line (the writer is asynchronous) is dropped when the file
/// does not end with a newline; every complete line must parse, a
/// persistent parse failure is spool corruption.
fn read_spool_events(spool_dir: &Path) -> Result<Vec<CadfEvent>> {
    let Ok(content) = std::fs::read_to_string(live_spool_file(spool_dir)) else {
        // The spool file appears once the first record is written.
        return Ok(Vec::new());
    };
    let mut lines: Vec<&str> = content.lines().collect();
    if !content.ends_with('\n') {
        lines.pop();
    }
    let mut events = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let event: CadfEvent = serde_json::from_str(line)
            .map_err(|e| eyre!("spool line does not parse as a CADF record: {e}\nline: {line}"))?;
        events.push(event);
    }
    Ok(events)
}

/// The `pending` and `success` lines of one audited provider operation.
fn find_pair<'a>(
    events: &'a [CadfEvent],
    action: &str,
    type_uri: &str,
    target_id: &str,
) -> (Option<&'a CadfEvent>, Option<&'a CadfEvent>) {
    let mut pending = None;
    let mut success = None;
    for event in events {
        let payload = event.payload();
        if payload.action() != action
            || payload.target().type_uri() != type_uri
            || payload.target().id() != target_id
        {
            continue;
        }
        match payload.outcome() {
            "pending" => {
                pending.get_or_insert(event);
            }
            "success" => {
                success.get_or_insert(event);
            }
            _ => {}
        }
    }
    (pending, success)
}

/// A fail-closed provider operation writes exactly one `pending` line and
/// one terminal line for the same event. `audited_op!` signs both with the
/// same dispatcher, so the terminal line's `seq` is greater than the
/// pending line's and both lines carry the request's correlation id (the
/// provider-side half of the correlation check; the perimeter line of an
/// authentication request carries the same request id as its
/// `correlation_id` tag).
fn assert_audited_pair(
    what: &str,
    action: &str,
    type_uri: &str,
    target_id: &str,
    events: &[CadfEvent],
) -> Result<()> {
    let (pending, success) = find_pair(events, action, type_uri, target_id);
    let pending = pending.ok_or_else(|| {
        eyre!(
            "{what}: no `pending` record (action `{action}`, target \
             `{target_id}`) in the spool"
        )
    })?;
    let success = success.ok_or_else(|| {
        eyre!(
            "{what}: no `success` record (action `{action}`, target \
             `{target_id}`) in the spool"
        )
    })?;
    assert!(
        success.seq() > pending.seq(),
        "{what}: the `success` line (seq {}) must follow the `pending` line (seq {})",
        success.seq(),
        pending.seq()
    );
    let correlation = pending.correlation_id();
    assert!(
        !correlation.is_empty(),
        "{what}: the `pending` line carries no correlation id"
    );
    assert_eq!(
        success.correlation_id(),
        correlation,
        "{what}: the `pending` and `success` lines of one request must \
         share the same correlation id"
    );
    Ok(())
}

/// Parse + verify every line of the spool, resolving each record's
/// `hmac_key_version` in the keyring exactly as a SIEM would.
fn verify_all(keyring: &HmacKeyring, events: &[CadfEvent]) -> Result<()> {
    // One throwaway dispatcher per key version; `verify_hmac` does not use
    // the channels (see `crates/cadf/tests/hmac_vectors.rs`).
    let mut dispatchers: HashMap<u64, Arc<AuditDispatcher>> = HashMap::new();
    for event in events {
        let version = event.payload().hmac_key_version();
        let key = keyring
            .node_key(&AUDIT_SERVICE, version, NODE_ID)
            .ok_or_else(|| {
                eyre!(
                    "event {} records hmac_key_version {version}, which the \
                     keyring does not know",
                    event.id()
                )
            })?
            .to_vec();
        let key = Arc::from(key.as_slice());
        let dispatcher = dispatchers.entry(version).or_insert_with(|| {
            let (dispatcher, _receivers) =
                AuditDispatcher::new(NODE_ID, "verify".to_string(), Arc::clone(&key), version);
            dispatcher
        });
        assert!(
            dispatcher.verify_hmac(event, &key),
            "HMAC verification failed for spool event {}",
            event.id()
        );
    }
    Ok(())
}

/// The id of the bootstrapped `admin` user in the default domain — the
/// initiator of the test's login perimeter record.
async fn find_admin_user_id(admin: &Arc<AsyncOpenStack>) -> Result<String> {
    let users = list_users(
        admin,
        UserListRequest {
            domain_id: Some(DOMAIN.to_string()),
            name: Some("admin".to_string()),
            unique_id: None,
        },
    )
    .await?;
    users
        .iter()
        .find(|user| user.name == "admin")
        .map(|user| user.id.clone())
        .ok_or_else(|| eyre!("no `admin` user found in domain `{DOMAIN}`"))
}

/// A successful admin login on the perimeter channel: action
/// `authenticate`, outcome `success`, targeting the keystone auth surface,
/// initiated by the admin user.
fn is_admin_login_success(event: &CadfEvent, admin_id: &str) -> bool {
    let payload = event.payload();
    payload.action() == "authenticate"
        && payload.outcome() == "success"
        && payload.target().type_uri() == AUTH_TYPE_URI
        && payload.initiator().id() == admin_id
}

fn user_create() -> Result<UserCreate> {
    Ok(UserCreateBuilder::default()
        .name(format!("audit-spool-{}", Uuid::new_v4().simple()))
        .domain_id(DOMAIN)
        .enabled(true)
        .build()?)
}

/// The live test: authenticate, mutate, read the spool, assert.
#[tokio::test]
async fn test_live_audit_spool_records() -> Result<()> {
    let Some(spool_dir) = spool_dir()? else {
        eprintln!(
            "skipping live audit spool test: {DEFAULT_SPOOL_DIR} does not exist \
             (run under the `api` nextest profile, which starts the server \
             via tools/start-api.sh)"
        );
        return Ok(());
    };
    let keyring = load_keyring(&spool_dir)?;

    let admin = get_system_scope_session().await?;
    let admin_id = find_admin_user_id(&admin).await?;

    // User create + delete: fail-closed provider records.
    let user = create_user(&admin, user_create()?).await?;
    let user_id = user.id.clone();
    delete_user(&admin, &user_id).await?;
    // The delete under test is the cleanup: opt out of the guard's leak
    // detection rather than issuing a second DELETE.
    user.into_inner();

    // API key create + revoke: provider records; the revoke record exists
    // only because this request carried an execution context.
    let provider = format!("audit-spool-{}", Uuid::new_v4().simple());
    let key = create_api_key(&admin, sample_api_key_create(DOMAIN, &provider)).await?;
    let client_id = key.api_key.client_id.clone();
    let revoked = revoke_api_key(&admin, DOMAIN, &client_id).await?;
    assert!(!revoked.enabled, "a revoked key must be disabled");
    key.into_inner();
    // The spool is written asynchronously; poll for every expected line.
    let deadline = Instant::now() + SPOOL_TIMEOUT;
    let mut events = read_spool_events(&spool_dir)?;
    loop {
        let (user_pending, user_success) = find_pair(&events, "delete", USER_TYPE_URI, &user_id);
        let (create_pending, create_success) =
            find_pair(&events, "create", USER_TYPE_URI, &user_id);
        let (key_create_pending, key_create_success) =
            find_pair(&events, "create", API_KEY_TYPE_URI, &client_id);
        let (key_revoke_pending, key_revoke_success) =
            find_pair(&events, "revoke", API_KEY_TYPE_URI, &client_id);
        let login = events
            .iter()
            .any(|event| is_admin_login_success(event, &admin_id));
        if user_pending.is_some()
            && user_success.is_some()
            && create_pending.is_some()
            && create_success.is_some()
            && key_create_pending.is_some()
            && key_create_success.is_some()
            && key_revoke_pending.is_some()
            && key_revoke_success.is_some()
            && login
        {
            break;
        }
        if Instant::now() >= deadline {
            bail!(
                "audit spool at {} did not contain the expected records \
                 within {SPOOL_TIMEOUT:?}: user-create pending/success = \
                 {}/{} , user-delete pending/success = {}/{}, api-key \
                 create pending/success = {}/{}, api-key revoke \
                 pending/success = {}/{}, admin login = {login}",
                live_spool_file(&spool_dir).display(),
                create_pending.is_some(),
                create_success.is_some(),
                user_pending.is_some(),
                user_success.is_some(),
                key_create_pending.is_some(),
                key_create_success.is_some(),
                key_revoke_pending.is_some(),
                key_revoke_success.is_some()
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
        events = read_spool_events(&spool_dir)?;
    }

    // Every line of the spool, not only this test's, must verify.
    verify_all(&keyring, &events)?;

    assert_audited_pair("user create", "create", USER_TYPE_URI, &user_id, &events)?;
    assert_audited_pair("user delete", "delete", USER_TYPE_URI, &user_id, &events)?;
    assert_audited_pair(
        "API key create",
        "create",
        API_KEY_TYPE_URI,
        &client_id,
        &events,
    )?;
    assert_audited_pair(
        "API key revoke",
        "revoke",
        API_KEY_TYPE_URI,
        &client_id,
        &events,
    )?;

    // The login is a perimeter record: best-effort channel, so a drop is
    // possible under load — but the record must be there and well-formed.
    let login = events
        .iter()
        .find(|event| is_admin_login_success(event, &admin_id))
        .ok_or_else(|| eyre!("no successful admin login perimeter record in the spool"))?;
    assert_eq!(
        login.payload().initiator().id(),
        admin_id,
        "the login perimeter record must be initiated by the admin user"
    );

    // A corrupted record is quarantined, never kept in a sealed segment; a
    // quarantine file in the live spool directory is always a bug.
    let quarantined = std::fs::read_dir(&spool_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".quarantine-"))
        .collect::<Vec<_>>();
    assert!(
        quarantined.is_empty(),
        "quarantined spool segments must not exist: {quarantined:?}"
    );

    Ok(())
}

/// Negative case: a tampered copy of a spool line must fail verification.
///
/// Signs a line with a fresh throwaway key and exercises the exact parse +
/// verify path of the live test, so it runs without a live spool: the
/// untampered line verifies, the tampered copy does not.
#[tokio::test]
async fn test_tampered_spool_line_fails_verification() -> Result<()> {
    let key: Arc<[u8]> =
        Arc::from(derive_audit_hmac_key(&AUDIT_SERVICE, &[7u8; 32], "tamper-node").as_slice());
    let (dispatcher, _receivers) = AuditDispatcher::new(
        "tamper-node",
        "boot-session".to_string(),
        Arc::clone(&key),
        1,
    );
    let payload = CadfEventPayload::new(
        "tamper-node:11111111-2222-3333-4444-555555555555".to_string(),
        "1.1".to_string(),
        "req-tamper".to_string(),
        "2026-10-06T00:00:00+00:00".to_string(),
        "delete".to_string(),
        "success".to_string(),
        None,
        Initiator::new("unknown".to_string(), None, None, None),
        Target::new("00000000-0000-0000-0000-000000000000", USER_TYPE_URI),
        Observer::new("tamper-node", "service/security/keystone/tamper-node"),
    );
    let event = payload.sign(&dispatcher);
    let line = serde_json::to_string(&event)?;

    let parsed: CadfEvent = serde_json::from_str(&line)?;
    assert!(
        dispatcher.verify_hmac(&parsed, &key),
        "an untampered line must verify"
    );

    // Flip the outcome in a copy of the line.
    let tampered = line.replace("\"outcome\":\"success\"", "\"outcome\":\"failure\"");
    assert_ne!(tampered, line, "the tamper must change the line");
    let parsed: CadfEvent = serde_json::from_str(&tampered)?;
    assert!(
        !dispatcher.verify_hmac(&parsed, &key),
        "a tampered line must fail verification"
    );
    Ok(())
}
