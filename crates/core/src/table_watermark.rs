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
//! # Table version watermarks
//!
//! The process-wide caches (catalog, roles, projects) only learn about
//! changes made by *another* process (replica, `keystone-manage`, direct SQL)
//! when their TTL expires. This module closes that gap with a *watermark*
//! per table:
//!
//! - the `table_version` table holds one counter per watched table;
//! - database triggers (installed by [`install`]) bump the counter on every
//!   `INSERT`, `UPDATE` and `DELETE` of the watched table, in the same
//!   transaction as the change;
//! - [`spawn`] polls the whole `table_version` table with one cheap query per
//!   interval and publishes the counters into [`TableWatermarks`];
//! - a cache remembers [`TableWatermarks::stamp`] of its tables when the
//!   value was loaded and serves the value for as long as the stamp is
//!   unchanged ([`TableWatermarks::is_fresh`]), without querying the
//!   database.
//!
//! The staleness window for foreign changes is the poll interval. While the
//! poller is not healthy (disabled, never polled, failing, triggers not
//! installed) [`TableWatermarks::stamp`] returns `None` and the caches fall
//! back to their TTL, so the feature can only ever tighten the staleness, not
//! loosen it.
//!
//! ## Trigger flavours
//!
//! | Backend    | Triggers per table                                    |
//! | ---------- | ----------------------------------------------------- |
//! | PostgreSQL | one `FOR EACH STATEMENT` trigger (also `TRUNCATE`)    |
//! | MySQL      | three `FOR EACH ROW` triggers (no statement triggers) |
//! | SQLite     | three `FOR EACH ROW` triggers (no statement triggers) |
//!
//! `TRUNCATE` does not fire triggers in MySQL and SQLite has none. Creating
//! triggers on MySQL with binary logging enabled requires the `TRIGGER`
//! privilege and, without `SUPER`, `log_bin_trust_function_creators=1`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use sea_orm::sea_query::{Alias, ColumnDef, Table};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, DbErr, Statement};
use tracing::{debug, info, warn};

use openstack_keystone_core_types::freshness::Freshness;

use crate::error::{DatabaseError, DbContextExt};
use crate::keystone::ServiceState;

/// Name of the table holding the counters.
pub const VERSION_TABLE: &str = "table_version";

/// Tables the catalog caches depend on.
pub const CATALOG_TABLES: &[&str] = &["service", "endpoint"];
/// Tables the role caches depend on.
pub const ROLE_TABLES: &[&str] = &["role", "role_option", "implied_role"];
/// Tables the project caches depend on.
pub const PROJECT_TABLES: &[&str] = &["project"];
/// The hard ceiling of `[database] projection_max_staleness_ms`.
pub const MAX_PROJECTION_STALENESS: Duration = Duration::from_secs(300);

/// The tolerance of the token validation path reads: what
/// `[database] projection_max_staleness_ms` allows, capped at
/// [`MAX_PROJECTION_STALENESS`]; linearizable when unset.
pub fn validation_freshness(config: &openstack_keystone_config::Config) -> Freshness {
    match config.database.projection_max_staleness_ms {
        0 => Freshness::Linearizable,
        ms => Freshness::MaxStaleness(Duration::from_millis(ms).min(MAX_PROJECTION_STALENESS)),
    }
}

/// Tables the identity driver caches projections of: the user options and
/// the passwords (only the expiry of the latest one; the hash is never
/// cached).
///
/// `local_user` is deliberately not watched: every failed login writes its
/// authentication counters, which would serialize concurrent logins on the
/// counter row and let anyone invalidate the caches by guessing passwords.
/// The projections do not need it: the link of a user to its local user is
/// read on every request, and a password row changes only through its own
/// table.
pub const IDENTITY_TABLES: &[&str] = &["user_option", "password"];

/// Poll interval used while the poller is disabled to notice a
/// configuration change.
const DISABLED_RECHECK: Duration = Duration::from_secs(5);

/// The poller is considered unhealthy once its last successful poll is older
/// than this many intervals.
const HEALTHY_INTERVALS: u64 = 3;

/// Lower bound of the health window, so a very short interval does not flap
/// on a slow poll.
const MIN_HEALTH_WINDOW_MS: u64 = 1000;

// ----------------------------------------------------------------------
// Installation (DDL)
// ----------------------------------------------------------------------

/// Reject names that could not be used as plain, unquoted identifiers. The
/// names come from constants, but they are interpolated into DDL.
fn check_identifier(name: &str) -> Result<(), DatabaseError> {
    if !name.is_empty()
        && name.len() <= 48
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
    {
        Ok(())
    } else {
        Err(DatabaseError::Sql {
            message: format!("`{name}` is not a valid table name for a watermark trigger"),
            context: "installing table watermark".to_string(),
        })
    }
}

/// Reject backends without trigger support in this module.
fn check_backend(backend: DatabaseBackend) -> Result<(), DatabaseError> {
    match backend {
        DatabaseBackend::Postgres | DatabaseBackend::MySql | DatabaseBackend::Sqlite => Ok(()),
        other => Err(DatabaseError::Sql {
            message: format!("table watermarks are not supported on {other:?}"),
            context: "installing table watermark".to_string(),
        }),
    }
}

/// Statement that increments the counter of `table`.
fn bump_sql(table: &str) -> String {
    format!("UPDATE {VERSION_TABLE} SET version = version + 1 WHERE table_name = '{table}'")
}

/// The statements that create the triggers bumping the counter of `table`.
///
/// Every statement is idempotent: an existing trigger is dropped first.
pub fn create_trigger_statements(backend: DatabaseBackend, table: &str) -> Vec<String> {
    let mut statements = drop_trigger_statements(backend, table);
    match backend {
        DatabaseBackend::Postgres => {
            statements.push(format!(
                "CREATE TRIGGER wm_{table} AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE \
                 ON {table} FOR EACH STATEMENT EXECUTE PROCEDURE keystone_bump_table_version('{table}')"
            ));
        }
        DatabaseBackend::MySql => {
            for (suffix, event) in [("ins", "INSERT"), ("upd", "UPDATE"), ("del", "DELETE")] {
                statements.push(format!(
                    "CREATE TRIGGER wm_{table}_{suffix} AFTER {event} ON {table} \
                     FOR EACH ROW {}",
                    bump_sql(table)
                ));
            }
        }
        DatabaseBackend::Sqlite => {
            for (suffix, event) in [("ins", "INSERT"), ("upd", "UPDATE"), ("del", "DELETE")] {
                statements.push(format!(
                    "CREATE TRIGGER wm_{table}_{suffix} AFTER {event} ON {table} \
                     FOR EACH ROW BEGIN {}; END",
                    bump_sql(table)
                ));
            }
        }
        // Rejected by `check_backend` before any statement is run.
        _ => {}
    }
    statements
}

/// The statements that drop the triggers of `table` (when present).
pub fn drop_trigger_statements(backend: DatabaseBackend, table: &str) -> Vec<String> {
    match backend {
        DatabaseBackend::Postgres => {
            vec![format!("DROP TRIGGER IF EXISTS wm_{table} ON {table}")]
        }
        DatabaseBackend::MySql | DatabaseBackend::Sqlite => ["ins", "upd", "del"]
            .iter()
            .map(|suffix| format!("DROP TRIGGER IF EXISTS wm_{table}_{suffix}"))
            .collect(),
        _ => Vec::new(),
    }
}

/// The PostgreSQL trigger function shared by all the watched tables.
const PG_FUNCTION: &str = "CREATE OR REPLACE FUNCTION keystone_bump_table_version() \
     RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
     UPDATE table_version SET version = version + 1 WHERE table_name = TG_ARGV[0]; \
     RETURN NULL; END $$";

/// Create the `table_version` table (when missing).
async fn ensure_version_table<C: ConnectionTrait>(conn: &C) -> Result<(), DatabaseError> {
    let stmt = Table::create()
        .table(Alias::new(VERSION_TABLE))
        .if_not_exists()
        .col(
            ColumnDef::new(Alias::new("table_name"))
                .string_len(64)
                .not_null()
                .primary_key(),
        )
        .col(
            ColumnDef::new(Alias::new("version"))
                .big_integer()
                .not_null()
                .default(0),
        )
        .to_owned();
    conn.execute(&stmt)
        .await
        .context("creating the table_version table")?;
    Ok(())
}

/// The statement that creates the counter row of `table` unless it exists.
///
/// Written out per backend: sea-query renders `do_nothing()` as the invalid
/// `ON DUPLICATE KEY IGNORE` on MySQL.
pub fn seed_counter_statement(backend: DatabaseBackend, table: &str) -> String {
    match backend {
        DatabaseBackend::MySql => {
            format!(
                "INSERT IGNORE INTO {VERSION_TABLE} (table_name, version) VALUES ('{table}', 1)"
            )
        }
        _ => format!(
            "INSERT INTO {VERSION_TABLE} (table_name, version) VALUES ('{table}', 1) \
             ON CONFLICT (table_name) DO NOTHING"
        ),
    }
}

/// Install the watermark of the `tables`: the `table_version` table, a
/// counter row and the triggers.
///
/// The tables must exist. The call is idempotent and is made from both the
/// `SqlDriver::setup` of a driver (fresh databases) and its migration
/// (upgraded databases).
pub async fn install<C: ConnectionTrait>(conn: &C, tables: &[&str]) -> Result<(), DatabaseError> {
    for table in tables {
        check_identifier(table)?;
    }
    let backend = conn.get_database_backend();
    check_backend(backend)?;
    ensure_version_table(conn).await?;
    if backend == DatabaseBackend::Postgres {
        conn.execute_unprepared(PG_FUNCTION)
            .await
            .context("creating the watermark trigger function")?;
    }
    for table in tables {
        conn.execute_unprepared(&seed_counter_statement(backend, table))
            .await
            .context("seeding the table_version counter")?;
        for statement in create_trigger_statements(backend, table) {
            conn.execute_unprepared(&statement)
                .await
                .context("creating the watermark trigger")?;
        }
    }
    Ok(())
}

/// Remove the triggers and the counters of the `tables`.
pub async fn uninstall<C: ConnectionTrait>(conn: &C, tables: &[&str]) -> Result<(), DatabaseError> {
    for table in tables {
        check_identifier(table)?;
    }
    let backend = conn.get_database_backend();
    check_backend(backend)?;
    for table in tables {
        for statement in drop_trigger_statements(backend, table) {
            conn.execute_unprepared(&statement)
                .await
                .context("dropping the watermark trigger")?;
        }
        conn.execute_unprepared(&format!(
            "DELETE FROM {VERSION_TABLE} WHERE table_name = '{table}'"
        ))
        .await
        .context("removing the table_version counter")?;
    }
    Ok(())
}

/// SQL that returns a row when the table `table` exists.
fn table_exists_statement(backend: DatabaseBackend, table: &str) -> String {
    match backend {
        DatabaseBackend::Postgres => format!(
            "SELECT 1 FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_name = '{table}'"
        ),
        DatabaseBackend::MySql => format!(
            "SELECT 1 FROM information_schema.tables \
             WHERE table_schema = DATABASE() AND table_name = '{table}'"
        ),
        _ => format!("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '{table}'"),
    }
}

/// Whether the table exists in the current schema.
pub async fn table_exists<C: ConnectionTrait>(conn: &C, table: &str) -> Result<bool, DbErr> {
    let backend = conn.get_database_backend();
    let sql = table_exists_statement(backend, table);
    Ok(conn
        .query_one_raw(Statement::from_string(backend, sql))
        .await?
        .is_some())
}

/// [`install`] for a migration. Tables that do not exist (yet) are skipped:
/// on a database created by `keystone-manage db sync` the driver `setup`
/// installs them, and a deployment that does not use the driver has none.
pub async fn install_migration(
    manager: &sea_orm_migration::SchemaManager<'_>,
    tables: &[&str],
) -> Result<(), DbErr> {
    let mut present = Vec::new();
    for table in tables {
        if table_exists(manager.get_connection(), table).await? {
            present.push(*table);
        }
    }
    install(manager.get_connection(), &present)
        .await
        .map_err(|err| DbErr::Custom(err.to_string()))
}

/// [`uninstall`] for a migration.
pub async fn uninstall_migration(
    manager: &sea_orm_migration::SchemaManager<'_>,
    tables: &[&str],
) -> Result<(), DbErr> {
    if !table_exists(manager.get_connection(), VERSION_TABLE).await? {
        return Ok(());
    }
    uninstall(manager.get_connection(), tables)
        .await
        .map_err(|err| DbErr::Custom(err.to_string()))
}

// ----------------------------------------------------------------------
// Runtime registry
// ----------------------------------------------------------------------

/// Milliseconds since the process-local epoch.
fn now_ms() -> u64 {
    static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);
    u64::try_from(EPOCH.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The last observed counters of the watched tables.
pub struct TableWatermarks {
    versions: ArcSwap<HashMap<String, i64>>,
    /// `now_ms() + 1` of the last successful poll; `0` when there was none.
    last_ok: AtomicU64,
    /// Configured poll interval in milliseconds; `0` when disabled.
    interval_ms: AtomicU64,
    /// Whether the previous poll failed; used to log transitions only.
    failing: AtomicBool,
    /// `now_ms() + 1` of the moment the published counters were *read*; `0`
    /// when there was no poll. A write committed after it is not part of the
    /// counters, so `now - snapshot` bounds how stale they can be.
    snapshot_ms: AtomicU64,
}

impl Default for TableWatermarks {
    fn default() -> Self {
        Self::new()
    }
}

impl TableWatermarks {
    /// Create an inactive registry: [`Self::stamp`] returns `None` until the
    /// poller is configured and has polled successfully.
    pub fn new() -> Self {
        Self {
            versions: ArcSwap::from_pointee(HashMap::new()),
            last_ok: AtomicU64::new(0),
            interval_ms: AtomicU64::new(0),
            failing: AtomicBool::new(false),
            snapshot_ms: AtomicU64::new(0),
        }
    }

    /// The process-wide registry.
    pub fn global() -> Arc<Self> {
        static GLOBAL: LazyLock<Arc<TableWatermarks>> =
            LazyLock::new(|| Arc::new(TableWatermarks::new()));
        GLOBAL.clone()
    }

    /// Set the poll interval; zero disables the watermarks.
    pub fn configure(&self, interval: Duration) {
        let ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
        if self.interval_ms.swap(ms, Ordering::AcqRel) != ms && ms == 0 {
            // Counters of a disabled poller must not be trusted again.
            self.last_ok.store(0, Ordering::Release);
        }
    }

    /// Publish the counters of a successful poll.
    pub fn publish(&self, versions: HashMap<String, i64>) {
        self.publish_read_at(versions, now_ms());
    }

    /// Publish counters that were read at `read_at` (see [`now_ms`]).
    fn publish_read_at(&self, versions: HashMap<String, i64>, read_at: u64) {
        self.versions.store(Arc::new(versions));
        self.snapshot_ms.store(read_at + 1, Ordering::Release);
        self.last_ok.store(now_ms() + 1, Ordering::Release);
    }

    /// Forget the published counters, e.g. after the connection was replaced
    /// by one that may point to another database.
    pub fn reset(&self) {
        self.last_ok.store(0, Ordering::Release);
        self.snapshot_ms.store(0, Ordering::Release);
        self.versions.store(Arc::new(HashMap::new()));
    }

    /// Copy what this registry observed into `other`.
    ///
    /// The providers that are built without a service state (catalog, role)
    /// still validate against [`Self::global`]; the poller of the connection
    /// feeds it until they read the counters of their connection like the
    /// drivers do.
    fn mirror_to(&self, other: &Self) {
        other
            .interval_ms
            .store(self.interval_ms.load(Ordering::Acquire), Ordering::Release);
        let snapshot = self.snapshot_ms.load(Ordering::Acquire);
        if snapshot == 0 {
            other.reset();
            return;
        }
        other.versions.store(self.versions.load_full());
        other.snapshot_ms.store(snapshot, Ordering::Release);
        other
            .last_ok
            .store(self.last_ok.load(Ordering::Acquire), Ordering::Release);
    }

    /// The configured poll interval; zero when the poller is disabled.
    pub fn interval(&self) -> Duration {
        Duration::from_millis(self.interval_ms.load(Ordering::Acquire))
    }

    /// How long ago the published counters were read.
    pub fn snapshot_age(&self) -> Option<Duration> {
        match self.snapshot_ms.load(Ordering::Acquire) {
            0 => None,
            read_at => Some(Duration::from_millis(now_ms().saturating_sub(read_at - 1))),
        }
    }

    /// Whether the counters are recent enough to be trusted.
    pub fn is_healthy(&self) -> bool {
        let interval = self.interval_ms.load(Ordering::Acquire);
        let last_ok = self.last_ok.load(Ordering::Acquire);
        if interval == 0 || last_ok == 0 {
            return false;
        }
        let window = interval
            .saturating_mul(HEALTHY_INTERVALS)
            .max(MIN_HEALTH_WINDOW_MS);
        now_ms().saturating_sub(last_ok - 1) <= window
    }

    /// Combined counter of the `tables`.
    ///
    /// The counters only grow, so their sum changes whenever any of them
    /// does. `None` when the poller is not healthy or a table has no counter
    /// (the triggers are not installed): the caller must then rely on its
    /// TTL.
    pub fn stamp(&self, tables: &[&str]) -> Option<u64> {
        if !self.is_healthy() {
            return None;
        }
        let versions = self.versions.load();
        let mut stamp = 0u64;
        for table in tables {
            let version = versions.get(*table)?;
            stamp = stamp.wrapping_add(u64::try_from(*version).ok()?);
        }
        Some(stamp)
    }

    /// The stamp a read that tolerates `freshness` may validate its cache
    /// entry against; `None` when the read has to go to the database.
    ///
    /// - [`Freshness::Linearizable`] never uses a stamp.
    /// - A tolerance below the poll interval cannot be guaranteed by a poller
    ///   that looks every interval, so it is a forced read.
    /// - A tolerance the current snapshot is already older than is a forced
    ///   read as well (a late or failing poller).
    pub fn stamp_for(&self, tables: &[&str], freshness: Freshness) -> Option<u64> {
        match freshness {
            Freshness::Linearizable => None,
            Freshness::MaxStaleness(bound) => {
                if bound.is_zero() || bound < self.interval() {
                    return None;
                }
                if self.snapshot_age()? > bound {
                    return None;
                }
                self.stamp(tables)
            }
            Freshness::Any => self.stamp(tables),
        }
    }

    /// Whether a value loaded at `loaded_at` under `loaded_stamp` (see
    /// [`Self::stamp`], taken *before* loading) may still be served.
    ///
    /// With a trustworthy stamp on both sides the value is valid exactly as
    /// long as the stamp is unchanged, however old it is. Otherwise the
    /// `ttl` decides.
    pub fn is_fresh(
        &self,
        tables: &[&str],
        loaded_at: Instant,
        loaded_stamp: Option<u64>,
        ttl: Duration,
    ) -> bool {
        match (loaded_stamp, self.stamp(tables)) {
            (Some(loaded), Some(current)) => loaded == current,
            _ => loaded_at.elapsed() < ttl,
        }
    }

    /// Read the counters and publish them.
    pub async fn poll(&self, conn: &DatabaseConnection) -> Result<(), DbErr> {
        let backend = conn.get_database_backend();
        let read_at = now_ms();
        let rows = conn
            .query_all_raw(Statement::from_string(
                backend,
                format!("SELECT table_name, version FROM {VERSION_TABLE}"),
            ))
            .await?;
        let mut versions = HashMap::with_capacity(rows.len());
        for row in rows {
            let name: String = row.try_get("", "table_name")?;
            let version: i64 = row.try_get("", "version")?;
            versions.insert(name, version);
        }
        self.publish_read_at(versions, read_at);
        Ok(())
    }

    /// Log poll failures and recoveries once per transition.
    fn record_poll(&self, result: &Result<(), DbErr>) {
        match result {
            Ok(()) => {
                if self.failing.swap(false, Ordering::AcqRel) {
                    info!("table watermark poll recovered");
                }
            }
            Err(error) => {
                if !self.failing.swap(true, Ordering::AcqRel) {
                    warn!(%error, "table watermark poll failed, caches fall back to their TTL");
                } else {
                    debug!(%error, "table watermark poll failed");
                }
            }
        }
    }
}

/// Start the poller of the global registry.
///
/// The interval is re-read from `[database] table_watermark_interval_ms` on
/// every round, so the poller can be enabled, retuned or disabled with a
/// configuration reload.
pub fn spawn(state: ServiceState) {
    tokio::spawn(async move {
        let watermarks = state.db.watermarks();
        loop {
            let interval = Duration::from_millis(
                state
                    .config_manager
                    .config
                    .read()
                    .await
                    .database
                    .table_watermark_interval_ms,
            );
            watermarks.configure(interval);
            let global = TableWatermarks::global();
            if interval.is_zero() {
                watermarks.mirror_to(&global);
                tokio::time::sleep(DISABLED_RECHECK).await;
                continue;
            }
            let result = watermarks.poll(&state.db.connection()).await;
            watermarks.record_poll(&result);
            watermarks.mirror_to(&global);
            tokio::time::sleep(interval).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use sea_orm::Database;

    use super::*;

    fn registry(interval_ms: u64) -> TableWatermarks {
        let wm = TableWatermarks::new();
        wm.configure(Duration::from_millis(interval_ms));
        wm
    }

    fn versions(pairs: &[(&str, i64)]) -> HashMap<String, i64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn test_inactive_until_polled() {
        let wm = registry(100);
        assert!(wm.stamp(&["a"]).is_none());
        wm.publish(versions(&[("a", 1)]));
        assert_eq!(Some(1), wm.stamp(&["a"]));
    }

    #[test]
    fn test_disabled_registry_has_no_stamp() {
        let wm = registry(0);
        wm.publish(versions(&[("a", 1)]));
        assert!(wm.stamp(&["a"]).is_none());
    }

    #[test]
    fn test_missing_table_has_no_stamp() {
        let wm = registry(100);
        wm.publish(versions(&[("a", 1)]));
        assert!(wm.stamp(&["a", "b"]).is_none());
    }

    #[test]
    fn test_stamp_changes_with_any_table() {
        let wm = registry(100);
        wm.publish(versions(&[("a", 1), ("b", 5)]));
        let before = wm.stamp(&["a", "b"]);
        wm.publish(versions(&[("a", 1), ("b", 6)]));
        assert_ne!(before, wm.stamp(&["a", "b"]));
        // An unrelated table does not move the stamp.
        wm.publish(versions(&[("a", 2), ("b", 6)]));
        assert_eq!(wm.stamp(&["b"]), Some(6));
    }

    #[test]
    fn test_unhealthy_after_missed_polls() {
        let wm = registry(1);
        wm.publish(versions(&[("a", 1)]));
        assert!(wm.is_healthy());
        std::thread::sleep(Duration::from_millis(MIN_HEALTH_WINDOW_MS + 100));
        assert!(!wm.is_healthy());
        assert!(wm.stamp(&["a"]).is_none());
    }

    #[test]
    fn test_freshness_follows_stamp_over_ttl() {
        let wm = registry(100);
        wm.publish(versions(&[("a", 1)]));
        let loaded_at = Instant::now();
        let stamp = wm.stamp(&["a"]);
        // Unchanged stamp: fresh even with an expired TTL.
        assert!(wm.is_fresh(&["a"], loaded_at, stamp, Duration::ZERO));
        // Changed stamp: stale even within the TTL.
        wm.publish(versions(&[("a", 2)]));
        assert!(!wm.is_fresh(&["a"], loaded_at, stamp, Duration::from_secs(60)));
    }

    #[test]
    fn test_freshness_falls_back_to_ttl() {
        let wm = registry(100);
        // Loaded while the poller had no data.
        let loaded_at = Instant::now();
        assert!(wm.is_fresh(&["a"], loaded_at, None, Duration::from_secs(60)));
        assert!(!wm.is_fresh(&["a"], loaded_at, None, Duration::ZERO));
    }

    #[test]
    fn test_invalid_identifier_is_rejected() {
        assert!(check_identifier("role_option").is_ok());
        assert!(check_identifier("a; DROP TABLE x").is_err());
        assert!(check_identifier("Role").is_err());
        assert!(check_identifier("").is_err());
    }

    #[test]
    fn test_trigger_statements_per_backend() {
        let pg = create_trigger_statements(DatabaseBackend::Postgres, "role");
        assert_eq!(2, pg.len());
        assert_eq!("DROP TRIGGER IF EXISTS wm_role ON role", pg[0]);
        assert!(pg[1].contains("FOR EACH STATEMENT"));
        assert!(pg[1].contains("keystone_bump_table_version('role')"));

        let mysql = create_trigger_statements(DatabaseBackend::MySql, "role");
        assert_eq!(6, mysql.len());
        assert!(mysql[3].starts_with("CREATE TRIGGER wm_role_ins AFTER INSERT ON role"));
        assert!(mysql[4].contains("AFTER UPDATE"));
        assert!(mysql[5].contains("AFTER DELETE"));
        assert!(mysql.iter().all(|s| !s.contains("BEGIN")));

        let sqlite = create_trigger_statements(DatabaseBackend::Sqlite, "role");
        assert_eq!(6, sqlite.len());
        assert!(sqlite[3].contains("BEGIN UPDATE table_version"));
        assert!(sqlite[3].ends_with("END"));
    }

    #[test]
    fn test_seed_statement_per_backend() {
        assert_eq!(
            "INSERT IGNORE INTO table_version (table_name, version) VALUES ('role', 1)",
            seed_counter_statement(DatabaseBackend::MySql, "role")
        );
        for backend in [DatabaseBackend::Postgres, DatabaseBackend::Sqlite] {
            assert!(
                seed_counter_statement(backend, "role")
                    .ends_with("ON CONFLICT (table_name) DO NOTHING")
            );
        }
    }

    async fn sqlite_with_role_table() -> DatabaseConnection {
        let conn = Database::connect("sqlite::memory:").await.unwrap();
        conn.execute_unprepared("CREATE TABLE role (id TEXT PRIMARY KEY, name TEXT)")
            .await
            .unwrap();
        conn
    }

    #[tokio::test]
    async fn test_sqlite_triggers_bump_counter() {
        let conn = sqlite_with_role_table().await;
        install(&conn, &["role"]).await.unwrap();
        // Idempotent.
        install(&conn, &["role"]).await.unwrap();

        let wm = registry(1000);
        wm.poll(&conn).await.unwrap();
        let mut last = wm.stamp(&["role"]).unwrap();

        for sql in [
            "INSERT INTO role (id, name) VALUES ('a', 'x')",
            "UPDATE role SET name = 'y' WHERE id = 'a'",
            "DELETE FROM role WHERE id = 'a'",
        ] {
            conn.execute_unprepared(sql).await.unwrap();
            wm.poll(&conn).await.unwrap();
            let stamp = wm.stamp(&["role"]).unwrap();
            assert!(stamp > last, "`{sql}` did not bump the counter");
            last = stamp;
        }
    }

    #[tokio::test]
    async fn test_sqlite_rolled_back_change_is_not_visible() {
        use sea_orm::TransactionTrait;
        let conn = sqlite_with_role_table().await;
        install(&conn, &["role"]).await.unwrap();
        let wm = registry(1000);
        wm.poll(&conn).await.unwrap();
        let before = wm.stamp(&["role"]);

        let txn = conn.begin().await.unwrap();
        txn.execute_unprepared("INSERT INTO role (id, name) VALUES ('a', 'x')")
            .await
            .unwrap();
        txn.rollback().await.unwrap();

        wm.poll(&conn).await.unwrap();
        assert_eq!(before, wm.stamp(&["role"]));
    }

    #[tokio::test]
    async fn test_sqlite_uninstall_stops_bumping() {
        let conn = sqlite_with_role_table().await;
        install(&conn, &["role"]).await.unwrap();
        uninstall(&conn, &["role"]).await.unwrap();
        conn.execute_unprepared("INSERT INTO role (id, name) VALUES ('a', 'x')")
            .await
            .unwrap();
        let wm = registry(1000);
        wm.poll(&conn).await.unwrap();
        // The counter row is gone, so the table has no stamp.
        assert!(wm.stamp(&["role"]).is_none());
    }

    #[tokio::test]
    async fn test_poll_without_version_table_fails() {
        let conn = Database::connect("sqlite::memory:").await.unwrap();
        let wm = registry(100);
        assert!(wm.poll(&conn).await.is_err());
        assert!(wm.stamp(&["role"]).is_none());
    }
}
