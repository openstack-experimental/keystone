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

//! # Per-request database time
//!
//! Sea-ORM measures each statement from the pool checkout to the last row
//! decoded, so the time includes waiting for a pooled connection and the
//! network round trip, not only the execution inside the database server.
//! The metric callback adds every statement to the counters of the request
//! that issued it; the `http.server` span reports the totals as
//! `db.time_us` and `db.queries`, so a trace shows what share of the request
//! the database accounts for.
//!
//! The counters live in a task local, so statements issued from a task the
//! handler spawned are not attributed to the request.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sea_orm::DatabaseConnection;

tokio::task_local! {
    static CURRENT: Arc<DbTiming>;
}

/// Statements issued by one request and the time they took.
#[derive(Debug, Default)]
pub struct DbTiming {
    micros: AtomicU64,
    queries: AtomicU64,
}

impl DbTiming {
    /// Total statement time in microseconds.
    pub fn micros(&self) -> u64 {
        self.micros.load(Ordering::Relaxed)
    }

    /// Number of statements.
    pub fn queries(&self) -> u64 {
        self.queries.load(Ordering::Relaxed)
    }
}

/// Run `fut` with a fresh counter and return it with the counter.
pub async fn scope<F: Future>(fut: F) -> (F::Output, Arc<DbTiming>) {
    let timing = Arc::new(DbTiming::default());
    let out = CURRENT.scope(timing.clone(), fut).await;
    (out, timing)
}

/// Attribute every statement on `conn` to the request that issued it.
pub fn install(conn: &mut DatabaseConnection) {
    conn.set_metric_callback(|info| {
        let _ = CURRENT.try_with(|timing| {
            timing.queries.fetch_add(1, Ordering::Relaxed);
            timing.micros.fetch_add(
                u64::try_from(info.elapsed.as_micros()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        });
    });
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn scope_returns_the_counters() {
        let (out, timing) = scope(async {
            let _ = CURRENT.try_with(|t| {
                t.queries.fetch_add(2, Ordering::Relaxed);
                t.micros.fetch_add(750, Ordering::Relaxed);
            });
            tokio::time::sleep(Duration::from_millis(1)).await;
            7
        })
        .await;
        assert_eq!(7, out);
        assert_eq!(2, timing.queries());
        assert_eq!(750, timing.micros());
    }

    #[test]
    fn outside_a_scope_nothing_is_counted() {
        assert!(CURRENT.try_with(|_| ()).is_err());
    }
}
