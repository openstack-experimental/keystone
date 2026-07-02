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

use goose::config::GooseDefault;
use goose::prelude::*;
use openstack_sdk::{AsyncOpenStack, config::ConfigFile};
use std::env;

mod seed;
mod v3;

use crate::v3::auth::{token_lifecycle, validate as validate_token};
use crate::v3::domain::list as domain_list;
use crate::v3::project::{
    create as project_create, delete as project_delete, list as project_list, show as project_show,
    show_random as project_show_random,
};
use crate::v3::user::{
    create as user_create, delete as user_delete, list as user_list, show as user_show,
    show_random as user_show_random,
};

/// Per-GooseUser session state shared across transactions.
pub struct Session {
    /// Admin-level token used for privileged operations.
    pub token: String,
    /// ID of the user created in on_start for UserCRUD scenario.
    pub user_id: Option<String>,
    /// ID of the project created in on_start for ProjectCRUD scenario.
    pub project_id: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    let host = get_host();
    let admin_token = get_admin_token().await;

    // Pre-populate the database so list endpoints operate on non-trivial data.
    let seed_state = seed::seed(&host, &admin_token).await;

    // Share the seeded ID pools with the catalog-read scenarios so virtual users
    // can pick random IDs without needing to issue their own list calls first.
    v3::user::set_seeded_ids(seed_state.user_ids.clone());
    v3::project::set_seeded_ids(seed_state.project_ids.clone());

    // Default to 30 users so all weighted scenarios get at least 1 user
    // (total weight = 20; 30 ensures proportional coverage).
    // Can be overridden by passing --users on the CLI.
    let attack = GooseAttack::initialize()?
        .set_default(GooseDefault::Users, 30usize)?
        // Read-heavy workload: list endpoints hit the most common production path.
        .register_scenario(
            scenario!("ReadHeavy")
                .set_weight(5)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(user_list))
                .register_transaction(transaction!(project_list))
                .register_transaction(transaction!(domain_list)),
        )
        // Token lifecycle: issue, validate, revoke — the hot path for every API request.
        .register_scenario(
            scenario!("TokenLifecycle")
                .set_weight(3)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(token_lifecycle)),
        )
        // Validates the existing token once per iteration (cheapest validation path).
        .register_scenario(
            scenario!("ValidateToken")
                .set_weight(2)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(validate_token)),
        )
        // User CRUD: each virtual user owns one user resource for the test duration.
        .register_scenario(
            scenario!("UserCRUD")
                .set_weight(2)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(user_create).set_on_start())
                .register_transaction(transaction!(user_show))
                .register_transaction(transaction!(user_delete).set_on_stop()),
        )
        // Project CRUD: each virtual user owns one project resource for the test duration.
        .register_scenario(
            scenario!("ProjectCRUD")
                .set_weight(1)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(project_create).set_on_start())
                .register_transaction(transaction!(project_show))
                .register_transaction(transaction!(project_delete).set_on_stop()),
        )
        // Catalog read: list all users then fetch a randomly chosen one from the
        // pre-seeded pool.  Exercises the list + point-read path under realistic
        // data volumes (100 seeded users).
        .register_scenario(
            scenario!("UserRead")
                .set_weight(4)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(user_list))
                .register_transaction(transaction!(user_show_random)),
        )
        // Catalog read: list all projects then fetch a randomly chosen one from the
        // pre-seeded pool.  Exercises the list + point-read path under realistic
        // data volumes (100 seeded projects).
        .register_scenario(
            scenario!("ProjectRead")
                .set_weight(3)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(project_list))
                .register_transaction(transaction!(project_show_random)),
        );

    attack.execute().await?;

    seed::cleanup(&host, &admin_token, &seed_state).await;

    Ok(())
}

/// Authenticate via the configured OS_CLOUD and store the token in session data.
pub async fn openstack_login(user: &mut GooseUser) -> TransactionResult {
    let cfg = ConfigFile::new().unwrap();
    let cloud_name = env::var("OS_CLOUD").unwrap_or("devstack".to_string());
    let profile = cfg.get_cloud_config(cloud_name).unwrap().unwrap();
    let session = AsyncOpenStack::new(&profile)
        .await
        .expect("cannot connect to the cloud");
    let token = session.get_auth_token().expect("no auth token in session");
    user.set_session_data(Session {
        token,
        user_id: None,
        project_id: None,
    });
    Ok(())
}

/// Return the --host argument value, falling back to localhost.
fn get_host() -> String {
    let args: Vec<String> = env::args().collect();
    for window in args.windows(2) {
        if window[0] == "--host" {
            return window[1].clone();
        }
    }
    "http://localhost:8080".to_string()
}

/// Obtain an admin token using the configured OS_CLOUD credentials.
async fn get_admin_token() -> String {
    let cfg = ConfigFile::new().expect("cannot read clouds.yaml");
    let cloud_name = env::var("OS_CLOUD").unwrap_or("devstack".to_string());
    let profile = cfg
        .get_cloud_config(cloud_name)
        .expect("cannot get cloud config")
        .expect("cloud not found");
    let session = AsyncOpenStack::new(&profile)
        .await
        .expect("cannot authenticate");
    session.get_auth_token().expect("no auth token")
}
