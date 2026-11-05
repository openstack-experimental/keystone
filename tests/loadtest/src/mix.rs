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

//! `LOADTEST_PROFILE=mix`: one scenario that draws every operation at random,
//! so the share of *requests* is fixed regardless of how long each takes (goose
//! weights pick a scenario per virtual user, which skews the request share as
//! soon as one scenario is slower, like the bcrypt ones).
//!
//! Request share (hashing share overridable with `LOADTEST_MIX_HASH_PCT`):
//! - 10% password hashing: half unscoped, half scoped password login (user
//!   passwords are set when the seed data is created, not during the mix)
//! - 50% token validation
//! - 30% reads (lists and point reads)
//! - 10% writes (project create + show, deleted only for
//!   `LOADTEST_MIX_DELETE_PCT` of the draws, so revocation events stay rare)

use goose::prelude::*;

use crate::v3::auth::lifecycle::validate;
use crate::v3::auth::password::{scoped, unscoped};
use crate::v3::domain::list as domain_list;
use crate::v3::project::{
    create as project_create, delete as project_delete, list as project_list, show as project_show,
    show_random as project_show_random,
};
use crate::v3::role::list as role_list;
use crate::v3::role_assignment::list as role_assignment_list;
use crate::v3::user::{list as user_list, show_random as user_show_random};

/// Share of the project writes that also delete the project in percent
/// (`LOADTEST_MIX_DELETE_PCT`, default 2). A delete removes the grants and
/// creates revocation events, so it is kept rare.
fn delete_pct() -> f64 {
    static PCT: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *PCT.get_or_init(|| {
        std::env::var("LOADTEST_MIX_DELETE_PCT")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| (0.0..=100.0).contains(v))
            .unwrap_or(2.0)
    })
}

/// Create and read a project (two requests); delete it only for a small share
/// of the draws (a third request).
async fn project_write(user: &mut GooseUser) -> TransactionResult {
    project_create(user).await?;
    project_show(user).await?;
    if fastrand::f64() * 100.0 < delete_pct() {
        project_delete(user).await?;
    }
    Ok(())
}

/// Hashing share of the requests in percent (`LOADTEST_MIX_HASH_PCT`, default
/// 10).
fn hash_pct() -> f64 {
    static PCT: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *PCT.get_or_init(|| {
        std::env::var("LOADTEST_MIX_HASH_PCT")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| (0.0..=100.0).contains(v))
            .unwrap_or(10.0)
    })
}

/// Token validation share of the requests in percent
/// (`LOADTEST_MIX_VALIDATE_PCT`). Unset keeps the 50:30:10 split of the
/// non-hashing requests.
fn validate_pct(rest: f64) -> f64 {
    static PCT: std::sync::OnceLock<Option<f64>> = std::sync::OnceLock::new();
    PCT.get_or_init(|| {
        std::env::var("LOADTEST_MIX_VALIDATE_PCT")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| (0.0..=100.0).contains(v))
    })
    .map_or(rest * 5.0 / 9.0, |v| v.min(rest))
}

/// Draw one operation. The write is drawn at a third of its request share
/// because it issues three requests.
pub async fn mix_op(user: &mut GooseUser) -> TransactionResult {
    let hash = hash_pct();
    let rest = 100.0 - hash;
    // Operations per 100 requests; the write issues three requests, so its
    // share counts a third.
    // The non-validation remainder splits 3:1 between reads and writes.
    let validate_w = validate_pct(rest);
    let others = rest - validate_w;
    let (read_w, write_w) = (others * 3.0 / 4.0, others / 4.0 / 3.0);
    let draw = fastrand::f64() * (hash + validate_w + read_w + write_w);
    if draw < hash / 2.0 {
        unscoped(user).await
    } else if draw < hash {
        scoped(user).await
    } else if draw < hash + validate_w {
        validate(user).await
    } else if draw < hash + validate_w + read_w {
        match fastrand::u8(..6) {
            0 => user_list(user).await,
            1 => project_list(user).await,
            2 => domain_list(user).await,
            3 => user_show_random(user).await,
            4 => project_show_random(user).await,
            _ => {
                if fastrand::bool() {
                    role_list(user).await
                } else {
                    role_assignment_list(user).await
                }
            }
        }
    } else {
        project_write(user).await
    }
}
