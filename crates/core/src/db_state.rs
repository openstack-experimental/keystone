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

//! Hot-swappable database connection handle.
//!
//! The active [`DatabaseConnection`] is an immutable snapshot behind
//! [`ArcSwap`], mirroring [`crate::rate_limit::RateLimitState`]: readers take
//! a lock-free snapshot via [`DbState::connection`], while
//! [`DbState::reconnect`] builds and pings a complete replacement connection
//! before atomically publishing it. A replacement that fails to connect or
//! fails its ping therefore leaves the last-known-good connection in service
//! rather than tearing it down.
//!
//! Reconnection is triggered only by a detected configuration change (see
//! `reconnect_db_on_config_change` in the `keystone` binary, which reacts to
//! `ConfigManager::notify_tx` - including a Vault-backed `[database]
//! connection` re-resolving to rotated credentials, or a `[database]
//! tls_cert_file`/`tls_key_file`/`tls_client_ca_file` rotating on disk (see
//! the `openstack_keystone::db_reload` module for that detection). There is
//! deliberately no periodic timer fallback. TLS parameters embedded
//! directly in the DSN query string (e.g. `sslrootcert=...`) remain static
//! for the process lifetime unless the DSN itself changes.

use arc_swap::ArcSwap;
use sea_orm::{ConnectOptions, Database, DatabaseConnection, DbErr};
use std::sync::Arc;
use tracing::warn;

/// Shared, hot-reloadable database connection held by the Keystone service.
pub struct DbState {
    current: ArcSwap<DatabaseConnection>,
}

impl DbState {
    /// Wrap an already-established connection.
    pub fn new(conn: DatabaseConnection) -> Self {
        Self {
            current: ArcSwap::new(Arc::new(conn)),
        }
    }

    /// Return a cheap clone of the currently active connection.
    ///
    /// `DatabaseConnection` wraps its pool behind an internal `Arc`, so this
    /// is an atomic load plus a refcount bump, not a new pool.
    pub fn connection(&self) -> DatabaseConnection {
        (**self.current.load()).clone()
    }

    /// Connect and verify the new options before publishing them.
    ///
    /// The new connection is pinged before it replaces the active one, so an
    /// unreachable host or stale/invalid rotated credential is rejected
    /// without disturbing traffic on the current connection. The
    /// superseded connection is closed in a detached background task; any
    /// caller that already holds a clone obtained from [`Self::connection`]
    /// before the swap keeps using it independently for the remainder of its
    /// in-flight work.
    pub async fn reconnect(&self, opt: ConnectOptions) -> Result<(), DbErr> {
        let new_conn = Database::connect(opt).await?;
        new_conn.ping().await?;

        let old = self.current.swap(Arc::new(new_conn));
        tokio::spawn(async move {
            if let Err(error) = old.close_by_ref().await {
                warn!(%error, "Failed to close superseded database connection");
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::ConnectionTrait;

    async fn sqlite_memory() -> DatabaseConnection {
        Database::connect("sqlite::memory:")
            .await
            .expect("connect to in-memory sqlite")
    }

    #[tokio::test]
    async fn connection_returns_the_wrapped_connection() {
        let conn = sqlite_memory().await;
        let state = DbState::new(conn);

        state
            .connection()
            .ping()
            .await
            .expect("wrapped connection should be usable");
    }

    #[tokio::test]
    async fn reconnect_swaps_to_the_new_connection() {
        let first = sqlite_memory().await;
        let state = DbState::new(first);

        let pre_swap = state.connection();
        pre_swap
            .execute_unprepared("CREATE TABLE marker (id INTEGER)")
            .await
            .expect("create marker table on original connection");

        // `sqlite::memory:` mints a brand-new, independent in-memory
        // database on every `Database::connect` call, so reconnecting to the
        // same DSN string still proves the swap: the table created above
        // must be absent from the post-swap connection.
        let opt = ConnectOptions::new("sqlite::memory:");
        state
            .reconnect(opt)
            .await
            .expect("reconnect to a valid DSN should succeed");

        let post_swap = state.connection();
        let result = post_swap.execute_unprepared("SELECT * FROM marker").await;
        assert!(
            result.is_err(),
            "post-swap connection must not see state from the pre-swap connection"
        );
    }

    #[tokio::test]
    async fn reconnect_to_invalid_dsn_keeps_last_known_good_connection() {
        let conn = sqlite_memory().await;
        let state = DbState::new(conn);

        state
            .connection()
            .ping()
            .await
            .expect("original connection should be usable before failed reconnect");

        // A malformed URL fails to parse immediately in `Database::connect`,
        // so this is fast and deterministic (no network I/O involved).
        let bad_opt = ConnectOptions::new("totally-not-a-database-url");
        let result = state.reconnect(bad_opt).await;
        assert!(result.is_err(), "reconnect to an invalid DSN must fail");

        state
            .connection()
            .ping()
            .await
            .expect("original connection must still be in service after a failed reconnect");
    }
}
