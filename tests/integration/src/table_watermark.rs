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
//
// SPDX-License-Identifier: Apache-2.0
//! Table version watermarks on the real backend.
//!
//! The triggers are backend specific (statement level on PostgreSQL, row
//! level on MySQL and SQLite), so these tests run against whatever
//! `DATABASE_URL` points to.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use eyre::Result;
use sea_orm::{ConnectionTrait, DatabaseBackend, TransactionTrait};
use tracing_test::traced_test;

use openstack_keystone_core::catalog::cache::CatalogCache;
use openstack_keystone_core::table_watermark::{
    CATALOG_TABLES, PROJECT_TABLES, ROLE_TABLES, TableWatermarks,
};
use openstack_keystone_core_types::catalog::ServiceCreate;

use crate::catalog::create_service;
use crate::common::get_state;
use crate::{create_domain, create_project, create_role};

fn registry() -> TableWatermarks {
    let wm = TableWatermarks::new();
    wm.configure(Duration::from_secs(1));
    wm
}

async fn stamps(wm: &TableWatermarks, db: &sea_orm::DatabaseConnection) -> [u64; 3] {
    wm.poll(db).await.unwrap();
    [CATALOG_TABLES, ROLE_TABLES, PROJECT_TABLES]
        .map(|tables| wm.stamp(tables).expect("counters of the watched tables"))
}

fn service_create() -> ServiceCreate {
    ServiceCreate {
        enabled: true,
        extra: HashMap::new(),
        id: None,
        r#type: Some("compute".to_string()),
    }
}

const INSERT_SERVICE: &str =
    "INSERT INTO service (id, type, enabled, extra) VALUES ('wm-raw', 'raw', true, '{}')";

#[traced_test]
#[tokio::test]
async fn test_provider_writes_move_only_their_watermark() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    let wm = registry();
    let [catalog, role, project] = stamps(&wm, &db).await;

    let service = create_service(&state, service_create()).await?;
    let [catalog_2, role_2, project_2] = stamps(&wm, &db).await;
    assert!(catalog_2 > catalog);
    assert_eq!((role, project), (role_2, project_2));

    let _role = create_role!(state)?;
    let [catalog_3, role_3, project_3] = stamps(&wm, &db).await;
    assert!(role_3 > role_2);
    assert_eq!((catalog_2, project_2), (catalog_3, project_3));

    let domain = create_domain!(state)?;
    let _project = create_project!(state, domain.id.clone())?;
    let [catalog_4, role_4, project_4] = stamps(&wm, &db).await;
    assert!(project_4 > project_3);
    assert_eq!((catalog_3, role_3), (catalog_4, role_4));

    drop(service);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_raw_statements_move_the_watermark() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    let wm = registry();
    let mut last = stamps(&wm, &db).await[0];

    for sql in [
        INSERT_SERVICE,
        "UPDATE service SET type = 'changed' WHERE id = 'wm-raw'",
        "DELETE FROM service WHERE id = 'wm-raw'",
    ] {
        db.execute_unprepared(sql).await?;
        let now = stamps(&wm, &db).await[0];
        assert!(now > last, "`{sql}` did not move the watermark");
        last = now;
    }

    // A statement touching no row does not have to move it (statement
    // level triggers do, row level ones do not); it must never go backwards.
    db.execute_unprepared("DELETE FROM service WHERE id = 'wm-none'")
        .await?;
    assert!(stamps(&wm, &db).await[0] >= last);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_rolled_back_write_is_not_visible() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    let wm = registry();
    let before = stamps(&wm, &db).await;

    let txn = db.begin().await?;
    txn.execute_unprepared(INSERT_SERVICE).await?;
    txn.rollback().await?;

    assert_eq!(before, stamps(&wm, &db).await);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_truncate_moves_the_watermark_on_postgres() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    if db.get_database_backend() != DatabaseBackend::Postgres {
        // MySQL does not fire triggers for TRUNCATE and SQLite has none.
        return Ok(());
    }
    let wm = registry();
    let before = stamps(&wm, &db).await[0];
    db.execute_unprepared("TRUNCATE service CASCADE").await?;
    assert!(stamps(&wm, &db).await[0] > before);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_setup_is_idempotent() -> Result<()> {
    use openstack_keystone_core::table_watermark::install;

    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    let wm = registry();
    let before = stamps(&wm, &db).await;
    // Installing again keeps the counters and the triggers.
    install(&db, CATALOG_TABLES).await?;
    install(&db, ROLE_TABLES).await?;
    install(&db, PROJECT_TABLES).await?;
    assert_eq!(before, stamps(&wm, &db).await);

    db.execute_unprepared(INSERT_SERVICE).await?;
    assert!(stamps(&wm, &db).await[0] > before[0]);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_foreign_write_reloads_the_cache() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    let wm = std::sync::Arc::new(registry());
    wm.poll(&db).await?;
    // The TTL alone would drop the entry long before the checks below.
    let cache = CatalogCache::with_watermarks(Duration::from_millis(1), wm.clone());
    let loads = AtomicUsize::new(0);
    let load = || async {
        loads.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    };

    cache.get_or_load(true, load).await?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    cache.get_or_load(true, load).await?;
    assert_eq!(1, loads.load(Ordering::SeqCst), "unchanged tables reload");

    // Another process writes; nothing is invalidated locally.
    db.execute_unprepared(INSERT_SERVICE).await?;
    // Not visible before the poller runs.
    cache.get_or_load(true, load).await?;
    assert_eq!(1, loads.load(Ordering::SeqCst));

    wm.poll(&db).await?;
    cache.get_or_load(true, load).await?;
    assert_eq!(2, loads.load(Ordering::SeqCst), "foreign write not noticed");
    cache.get_or_load(true, load).await?;
    assert_eq!(2, loads.load(Ordering::SeqCst));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_table_exists_and_reinstall() -> Result<()> {
    use openstack_keystone_core::table_watermark::{VERSION_TABLE, table_exists, uninstall};

    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    // The check the migrations rely on, on every backend.
    assert!(table_exists(&db, "service").await?);
    assert!(table_exists(&db, VERSION_TABLE).await?);
    assert!(!table_exists(&db, "no_such_table").await?);

    // Down, then up again (a migration revert and re-apply).
    uninstall(&db, CATALOG_TABLES).await?;
    let wm = registry();
    wm.poll(&db).await?;
    assert!(wm.stamp(CATALOG_TABLES).is_none());
    db.execute_unprepared(INSERT_SERVICE).await?;
    db.execute_unprepared("DELETE FROM service WHERE id = 'wm-raw'")
        .await?;

    openstack_keystone_core::table_watermark::install(&db, CATALOG_TABLES).await?;
    let before = stamps(&wm, &db).await[0];
    db.execute_unprepared(INSERT_SERVICE).await?;
    assert!(stamps(&wm, &db).await[0] > before);
    Ok(())
}
