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
//! Test add user group membership functionality.

use std::time::Instant;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_config::PasswordHashingAlgo;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::identity::*;

use crate::common::get_state_with_config;
use crate::create_domain;

#[tokio::test]
#[traced_test]
async fn test_list() -> Result<()> {
    let (state, _tmp) = get_state_with_config(|_| {}).await?;
    let domain = create_domain!(state)?;
    let cnt = 20;

    for _ in 0..cnt {
        state
            .provider
            .get_identity_provider()
            .create_user(
                &ExecutionContext::internal(&state),
                UserCreateBuilder::default()
                    .name(Uuid::new_v4().to_string())
                    .domain_id(domain.id.clone())
                    .enabled(true)
                    .build()?,
            )
            .await?;
    }

    let users: Vec<UserResponse> = state
        .provider
        .get_identity_provider()
        .list_users(
            &ExecutionContext::internal(&state),
            &UserListParameters::default(),
        )
        .await?
        .into_iter()
        .collect();
    assert!(users.len() >= cnt, "{} >= {}", users.len(), cnt);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_mixed_user_types() -> Result<()> {
    let (state, _tmp) = get_state_with_config(|_| {}).await?;
    let domain = create_domain!(state)?;
    let prov = state.provider.get_identity_provider();

    prov.create_user(
        &ExecutionContext::internal(&state),
        UserCreateBuilder::default()
            .name(format!("local-{}", Uuid::new_v4()))
            .domain_id(domain.id.clone())
            .enabled(true)
            .password("foobar123")
            .build()?,
    )
    .await?;

    prov.create_user(
        &ExecutionContext::internal(&state),
        UserCreateBuilder::default()
            .name(format!("nonlocal-{}", Uuid::new_v4()))
            .domain_id(domain.id.clone())
            .enabled(true)
            .user_type(UserType::NonLocal)
            .build()?,
    )
    .await?;

    let fed = FederationBuilder::default()
        .idp_id("idp_id")
        .unique_id("uid")
        .protocols(vec![FederationProtocol {
            protocol_id: "oidc".into(),
            unique_id: "uid".into(),
        }])
        .build()?;
    prov.create_user(
        &ExecutionContext::internal(&state),
        UserCreateBuilder::default()
            .name(format!("federated-{}", Uuid::new_v4()))
            .domain_id(domain.id.clone())
            .enabled(true)
            .federated(vec![fed])
            .build()?,
    )
    .await?;

    let users: Vec<UserResponse> = prov
        .list_users(
            &ExecutionContext::internal(&state),
            &UserListParameters {
                domain_id: Some(domain.id.clone()),
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .collect();

    let local_count = users
        .iter()
        .filter(|u| u.name.starts_with("local-"))
        .count();
    let nonlocal_count = users
        .iter()
        .filter(|u| u.name.starts_with("nonlocal-"))
        .count();
    let federated_count = users
        .iter()
        .filter(|u| u.name.starts_with("federated-"))
        .count();

    assert_eq!(
        users.len(),
        3,
        "expected 3 users (local/nonlocal/federated), got {}: {:?}",
        users.len(),
        users.iter().map(|u| &u.name).collect::<Vec<_>>()
    );
    assert_eq!(local_count, 1, "local user missing");
    assert_eq!(nonlocal_count, 1, "nonlocal user missing");
    assert_eq!(federated_count, 1, "federated user missing");

    Ok(())
}

/// Profile user-list performance with a configurable user count.
///
/// # Design
/// Uses dummy password hashing (PasswordHashingAlgo::None) so that the test
/// setup (user creation time) is not dominated by bcrypt. Only the user-listing
/// phase is measured — no password comparison happens there, only password
/// expiration is computed from pre-stored `expires_at` columns.
///
/// # Tune
/// Adjust values in the `// ---- tune these ----` block.
///
/// # Expected output
/// ```text
/// profile_user_list: creating 1000 users (1000 w/ password, 0 w/o)
///   create_users:  1000 users in 0.668s (0.67ms/user)
///   list_users:    8 attempts, avg 0.106s, best 0.103s
///   list_users filtered:   1000 users in domain, 8 attempts, avg 0.098s, best 0.096s
/// ```
///
/// # Usage
/// ```text
/// cargo nextest run -p test_integration --nocapture -- profile_user_list
/// cargo nextest run -p test_integration --nocapture --profile raft -- profile_user_list
/// ```
#[tokio::test]
//#[traced_test]
async fn profile_user_list() -> Result<()> {
    // ---- tune these ----
    let user_count = 5000;
    let password_pct = 100;
    let warmup_iterations = 2;
    let measured_iterations = 8;
    // ---------------------

    // Use get_state_with_config() so dummy hashing (PasswordHashingAlgo::None)
    // is applied BEFORE Provider::new() caches the config. Mutating
    // state.config_manager.config AFTER construction does not propagate to the
    // password hasher — it reads its own captured copy.
    let (state, _tmp) = get_state_with_config(|cfg| {
        cfg.identity.password_hashing_algorithm = PasswordHashingAlgo::None;
    })
    .await?;
    let domain = create_domain!(state)?;

    let password_count = (user_count as f64 * password_pct as f64 / 100.0).floor() as usize;

    println!(
        "{}: creating {} users ({} w/ password, {} w/o)",
        "profile_user_list",
        user_count,
        password_count,
        user_count - password_count
    );

    let t0 = Instant::now();

    for i in 0..user_count {
        if i < password_count {
            state
                .provider
                .get_identity_provider()
                .create_user(
                    &ExecutionContext::internal(&state),
                    UserCreateBuilder::default()
                        .name(Uuid::new_v4().to_string())
                        .domain_id(domain.id.clone())
                        .enabled(true)
                        .password(format!("pass_{i}"))
                        .build()?,
                )
                .await?;
        } else {
            state
                .provider
                .get_identity_provider()
                .create_user(
                    &ExecutionContext::internal(&state),
                    UserCreateBuilder::default()
                        .name(Uuid::new_v4().to_string())
                        .domain_id(domain.id.clone())
                        .enabled(true)
                        .build()?,
                )
                .await?;
        }
    }
    let elapsed_create = t0.elapsed();
    println!(
        "  create_users:  {} users in {:.3}s ({:.2}ms/user)",
        user_count,
        elapsed_create.as_secs_f64(),
        elapsed_create.as_secs_f64() * 1_000.0 / user_count as f64
    );

    // --- full list (no filter) ---
    let mut list_times = Vec::new();
    let mut iteration = 0;
    while iteration < warmup_iterations + measured_iterations {
        let t0 = Instant::now();

        let users: Vec<UserResponse> = state
            .provider
            .get_identity_provider()
            .list_users(
                &ExecutionContext::internal(&state),
                &UserListParameters::default(),
            )
            .await?
            .into_iter()
            .collect();

        let elapsed = t0.elapsed();
        if iteration >= warmup_iterations {
            list_times.push(elapsed.as_secs_f64());
        }

        assert!(
            users.len() >= user_count,
            "got {} users, expected >={}",
            users.len(),
            user_count
        );
        iteration += 1;
    }

    let avg = list_times.iter().sum::<f64>() / list_times.len() as f64;
    let best = list_times.iter().copied().fold(f64::MAX, f64::min);
    println!(
        "  list_users:    {} attempts, avg {:.3}s, best {:.3}s",
        list_times.len(),
        avg,
        best
    );

    // --- domain-filtered list ---
    let params = UserListParameters {
        domain_id: Some(domain.id.clone()),
        ..Default::default()
    };
    list_times.clear();
    iteration = 0;
    while iteration < warmup_iterations + measured_iterations {
        let t0 = Instant::now();

        let users: Vec<UserResponse> = state
            .provider
            .get_identity_provider()
            .list_users(&ExecutionContext::internal(&state), &params)
            .await?
            .into_iter()
            .collect();

        let elapsed = t0.elapsed();
        if iteration >= warmup_iterations {
            list_times.push(elapsed.as_secs_f64());
        }

        assert_eq!(users.len(), user_count, "domain-filtered count mismatch");
        iteration += 1;
    }

    let avg = list_times.iter().sum::<f64>() / list_times.len() as f64;
    let best = list_times.iter().copied().fold(f64::MAX, f64::min);
    println!(
        "  list_users filtered:   {} users in domain, {} attempts, avg {:.3}s, best {:.3}s",
        user_count,
        list_times.len(),
        avg,
        best
    );

    Ok(())
}
