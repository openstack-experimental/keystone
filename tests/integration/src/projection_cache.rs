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
//! Driver-side projection caches on the real backend.
//!
//! The readers state how stale the result may be (`Freshness`); the SQL
//! drivers serve the non-secret projections (password expiry of a user, the
//! domain of a project) from a cache validated by the table watermarks only
//! when that tolerance allows it. A *foreign* write is a raw statement: it
//! bypasses the driver, so only the watermark can tell.

use std::time::Duration;

use eyre::Result;
use sea_orm::ConnectionTrait;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::freshness::Freshness;
use openstack_keystone_core_types::identity::UserCreateBuilder;

use crate::common::get_state;
use crate::{create_domain, create_project};

/// 2100-01-01T00:00:00Z in microseconds.
const EXPIRY_A: i64 = 4_102_444_800_000_000;
/// 2101-01-01T00:00:00Z in microseconds.
const EXPIRY_B: i64 = 4_133_980_800_000_000;

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const RELAXED: Freshness = Freshness::MaxStaleness(Duration::from_secs(30));
/// Below the poll interval: cannot be guaranteed, a forced read.
const TIGHT: Freshness = Freshness::MaxStaleness(Duration::from_millis(100));

async fn password_expiry(
    state: &openstack_keystone_core::keystone::ServiceState,
    user_id: &str,
    freshness: Freshness,
) -> Result<Option<i64>> {
    let ctx = ExecutionContext::internal(state).with_freshness(freshness);
    Ok(state
        .provider
        .get_identity_provider()
        .get_user(&ctx, user_id)
        .await?
        .and_then(|user| user.password_expires_at)
        .map(|expiry| expiry.timestamp_micros()))
}

async fn project_domain_id(
    state: &openstack_keystone_core::keystone::ServiceState,
    project_id: &str,
    freshness: Freshness,
) -> Result<Option<String>> {
    let ctx = ExecutionContext::internal(state).with_freshness(freshness);
    Ok(state
        .provider
        .get_resource_provider()
        .get_project_domain_id(&ctx, project_id)
        .await?)
}

#[traced_test]
#[tokio::test]
async fn test_password_expiry_follows_the_stated_freshness() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    let wm = state.db.watermarks();
    wm.configure(POLL_INTERVAL);

    let domain = create_domain!(state)?;
    let user = crate::identity::create_user(
        &state,
        UserCreateBuilder::default()
            .name(uuid::Uuid::new_v4().simple().to_string())
            .domain_id(domain.id.clone())
            .password("foobar")
            .build()?,
    )
    .await?;
    let set_expiry = |micros: i64| {
        format!(
            "UPDATE password SET expires_at_int = {micros} WHERE local_user_id IN \
             (SELECT id FROM local_user WHERE user_id = '{}')",
            user.id
        )
    };

    db.execute_unprepared(&set_expiry(EXPIRY_A)).await?;
    wm.poll(&db).await?;
    assert_eq!(
        Some(EXPIRY_A),
        password_expiry(&state, &user.id, RELAXED).await?
    );

    // Another replica shortens or extends the expiry: nothing here knows yet.
    db.execute_unprepared(&set_expiry(EXPIRY_B)).await?;
    assert_eq!(
        Some(EXPIRY_A),
        password_expiry(&state, &user.id, RELAXED).await?,
        "a relaxed read before the poll is served from the cache"
    );
    assert_eq!(
        Some(EXPIRY_B),
        password_expiry(&state, &user.id, Freshness::Linearizable).await?,
        "a linearizable read must see every committed write"
    );
    assert_eq!(
        Some(EXPIRY_B),
        password_expiry(&state, &user.id, TIGHT).await?,
        "a tolerance below the poll interval is a forced read"
    );

    // The poller notices the foreign write.
    wm.poll(&db).await?;
    assert_eq!(
        Some(EXPIRY_B),
        password_expiry(&state, &user.id, RELAXED).await?
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_unhealthy_poller_is_a_forced_read() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    let wm = state.db.watermarks();
    wm.configure(POLL_INTERVAL);

    let domain = create_domain!(state)?;
    let user = crate::identity::create_user(
        &state,
        UserCreateBuilder::default()
            .name(uuid::Uuid::new_v4().simple().to_string())
            .domain_id(domain.id.clone())
            .password("foobar")
            .build()?,
    )
    .await?;
    let set_expiry = |micros: i64| {
        format!(
            "UPDATE password SET expires_at_int = {micros} WHERE local_user_id IN \
             (SELECT id FROM local_user WHERE user_id = '{}')",
            user.id
        )
    };
    db.execute_unprepared(&set_expiry(EXPIRY_A)).await?;
    wm.poll(&db).await?;
    assert_eq!(
        Some(EXPIRY_A),
        password_expiry(&state, &user.id, RELAXED).await?
    );

    db.execute_unprepared(&set_expiry(EXPIRY_B)).await?;
    // The connection was replaced: the counters are not trusted until the
    // next successful poll.
    wm.reset();
    assert_eq!(
        Some(EXPIRY_B),
        password_expiry(&state, &user.id, RELAXED).await?
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_project_domain_follows_the_stated_freshness() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    let wm = state.db.watermarks();
    wm.configure(POLL_INTERVAL);

    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    wm.poll(&db).await?;
    assert_eq!(
        Some(domain.id.clone()),
        project_domain_id(&state, &project.id, RELAXED).await?
    );

    // Deleted by another replica.
    db.execute_unprepared(&format!("DELETE FROM project WHERE id = '{}'", project.id))
        .await?;
    assert_eq!(
        Some(domain.id.clone()),
        project_domain_id(&state, &project.id, RELAXED).await?,
        "a relaxed read before the poll is served from the cache"
    );
    assert_eq!(
        None,
        project_domain_id(&state, &project.id, Freshness::Linearizable).await?
    );
    assert_eq!(None, project_domain_id(&state, &project.id, TIGHT).await?);

    wm.poll(&db).await?;
    assert_eq!(None, project_domain_id(&state, &project.id, RELAXED).await?);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_own_writes_are_visible_immediately() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    let wm = state.db.watermarks();
    wm.configure(POLL_INTERVAL);

    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    wm.poll(&db).await?;
    assert!(
        project_domain_id(&state, &project.id, RELAXED)
            .await?
            .is_some()
    );

    // The same replica deletes: no poll in between.
    state
        .provider
        .get_resource_provider()
        .delete_project(&ExecutionContext::internal(&state), &project.id)
        .await?;
    assert_eq!(None, project_domain_id(&state, &project.id, RELAXED).await?);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_missing_project_is_not_cached() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    let wm = state.db.watermarks();
    wm.configure(POLL_INTERVAL);
    wm.poll(&db).await?;

    assert_eq!(
        None,
        project_domain_id(&state, "no-such-project", RELAXED).await?
    );
    // The project appears (another replica) before the next poll: a cached
    // "does not exist" would hide it.
    let domain = create_domain!(state)?;
    db.execute_unprepared(&format!(
        "INSERT INTO project (id, name, domain_id, is_domain, enabled, extra) \
         VALUES ('late-project', 'late', '{}', false, true, '{{}}')",
        domain.id
    ))
    .await?;
    assert_eq!(
        Some(domain.id.clone()),
        project_domain_id(&state, "late-project", RELAXED).await?
    );
    db.execute_unprepared("DELETE FROM project WHERE id = 'late-project'")
        .await?;
    Ok(())
}

/// Rows removed by a foreign key cascade do not fire row triggers on MySQL
/// (documented InnoDB behaviour): the watermark of a child table misses them.
///
/// The projections stay correct because the parent row (`user`, `project`,
/// `local_user`) is read on every request and a projection is only used
/// together with it; this test pins the limitation so that nobody builds on
/// the child watermark alone.
#[traced_test]
#[tokio::test]
async fn test_cascade_deletes_and_the_child_watermark() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    let wm = state.db.watermarks();
    wm.configure(POLL_INTERVAL);
    let domain = create_domain!(state)?;
    let user = crate::identity::create_user(
        &state,
        UserCreateBuilder::default()
            .name(uuid::Uuid::new_v4().simple().to_string())
            .domain_id(domain.id.clone())
            .password("foobar")
            .build()?,
    )
    .await?;
    wm.poll(&db).await?;
    let before = wm.stamp(&["password"]).expect("password counter");
    db.execute_unprepared(&format!(
        "DELETE FROM local_user WHERE user_id = '{}'",
        user.id
    ))
    .await?;
    wm.poll(&db).await?;
    let after = wm.stamp(&["password"]).expect("password counter");
    if db.get_database_backend() == sea_orm::DatabaseBackend::MySql {
        assert_eq!(before, after, "MySQL started firing triggers on cascades");
    } else {
        assert!(after > before, "the cascade did not move the watermark");
    }
    Ok(())
}
