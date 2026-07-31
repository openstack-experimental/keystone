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
use openstack_sdk::{
    AsyncOpenStack,
    config::{CloudConfig, ConfigFile},
};
use std::env;

mod seed;
mod v3;
mod v4;

use crate::v3::auth::lifecycle::{token_lifecycle, validate as validate_token};
use crate::v3::auth::password::{
    invalid as password_auth_invalid, scoped as password_auth_scoped,
    unscoped as password_auth_unscoped,
};
use crate::v3::auth::rescope::{rescope_invalid_project, rescope_to_system};
use crate::v3::auth::system::system_scope_auth;
use crate::v3::domain::list as domain_list;
use crate::v3::project::{
    create as project_create, delete as project_delete, list as project_list, show as project_show,
    show_random as project_show_random,
};
use crate::v3::role::{
    create as role_create, delete as role_delete, list as role_list, show as role_show,
};
use crate::v3::role_assignment::{
    list as role_assignment_list, list_by_domain as role_assignment_list_by_domain,
    list_by_role as role_assignment_list_by_role, list_by_user as role_assignment_list_by_user,
};
use crate::v3::user::{
    create as user_create, delete as user_delete, list as user_list, show as user_show,
    show_random as user_show_random,
};
use crate::v4::api_key::{
    create as api_key_create, list as api_key_list, revoke as api_key_revoke,
    show as api_key_show,
};
use crate::v4::mapping::{
    create as mapping_create, delete as mapping_delete, list as mapping_list,
    show as mapping_show,
};
use crate::v4::oauth2::{
    create_client as oauth2_client_create, delete_client as oauth2_client_delete,
    jwks as oauth2_jwks, list_clients as oauth2_client_list,
    show_client as oauth2_client_show, well_known as oauth2_well_known,
};

/// Per-GooseUser session state shared across transactions.
pub struct Session {
    /// Admin-level token used for privileged operations.
    pub token: String,
    /// ID of the user created in on_start for UserCRUD scenario.
    pub user_id: Option<String>,
    /// ID of the project created in on_start for ProjectCRUD scenario.
    pub project_id: Option<String>,
    /// ID of the role created in on_start for RoleCRUD scenario.
    pub role_id: Option<String>,
    /// client_id of the API key created in on_start for ApiKeyCRUD scenario
    /// (raft-backed, ADR 0021).
    pub api_key_client_id: Option<String>,
    /// mapping_id of the ruleset created in on_start for MappingCRUD
    /// scenario (raft-backed, ADR 0020).
    pub mapping_id: Option<String>,
    /// provider_id of the OAuth2 client created in on_start for
    /// OAuth2ClientCRUD scenario (raft-backed, ADR 0026).
    pub oauth2_client_id: Option<String>,
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

    // Share seeded user credentials and the shared auth project with the
    // password-auth scenarios.
    v3::user::set_seeded_creds(seed_state.user_creds.clone());
    if let Some(auth_project_id) = &seed_state.auth_project_id {
        v3::user::set_auth_project_id(auth_project_id.clone());
    }
    if let Some(auth_role_id) = &seed_state.auth_role_id {
        v3::role_assignment::set_auth_role_id(auth_role_id.clone());
    }

    // Default to 45 users so all weighted scenarios get at least 1 user
    // (total weight = 36; 45 ensures proportional coverage).
    // Can be overridden by passing --users on the CLI. To actually run this
    // as a stress test, scale further with goose's own CLI flags, e.g.:
    //   --users 500 --hatch-rate 20 --run-time 10m
    let attack = GooseAttack::initialize()?
        .set_default(GooseDefault::Users, 45usize)?
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
        // Role CRUD: each virtual user owns one role resource for the test duration.
        .register_scenario(
            scenario!("RoleCRUD")
                .set_weight(1)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(role_create).set_on_start())
                .register_transaction(transaction!(role_show))
                .register_transaction(transaction!(role_delete).set_on_stop()),
        )
        // Dedicated role listing: exercises GET /v3/roles against the roles
        // bootstrap/CRUD scenarios keep populated (admin, manager, member,
        // reader, plus the auth-project's member role and any RoleCRUD churn).
        .register_scenario(
            scenario!("RoleList")
                .set_weight(2)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(role_list)),
        )
        // Role assignment listing: unfiltered plus the user.id/scope.domain.id/
        // role.id filter variants, all against the auth-project's seeded
        // (100 users x member role) assignments.
        .register_scenario(
            scenario!("RoleAssignmentList")
                .set_weight(3)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(role_assignment_list))
                .register_transaction(transaction!(role_assignment_list_by_user))
                .register_transaction(transaction!(role_assignment_list_by_domain))
                .register_transaction(transaction!(role_assignment_list_by_role)),
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
        )
        // Password auth: exercises the hot password-login path against the
        // pre-provisioned seeded users, both unscoped and project-scoped.
        .register_scenario(
            scenario!("PasswordAuth")
                .set_weight(4)?
                .register_transaction(transaction!(password_auth_unscoped))
                .register_transaction(transaction!(password_auth_scoped)),
        )
        // Password auth negative path: wrong password must be rejected (401).
        .register_scenario(
            scenario!("PasswordAuthNegative")
                .set_weight(1)?
                .register_transaction(transaction!(password_auth_invalid)),
        )
        // Rescope the OS_CLOUD-authenticated token to system scope.
        .register_scenario(
            scenario!("Rescope")
                .set_weight(2)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(rescope_to_system)),
        )
        // Rescope negative path: rescoping to a nonexistent project must fail.
        .register_scenario(
            scenario!("RescopeNegative")
                .set_weight(1)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(rescope_invalid_project)),
        )
        // System-scoped auth using the initial bootstrap admin credentials.
        .register_scenario(
            scenario!("SystemScopeAuth")
                .set_weight(2)?
                .register_transaction(transaction!(system_scope_auth)),
        )
        // Raft-backed API Key CRUD (ADR 0021): create/revoke go through
        // api-key-driver-raft's log-append + quorum-commit write path.
        .register_scenario(
            scenario!("ApiKeyCRUD")
                .set_weight(1)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(api_key_create).set_on_start())
                .register_transaction(transaction!(api_key_show))
                .register_transaction(transaction!(api_key_list))
                .register_transaction(transaction!(api_key_revoke).set_on_stop()),
        )
        // Raft-backed Mapping ruleset CRUD (ADR 0020): mapping-driver-raft is
        // the largest raft driver -- rules carry nested claim/identity/role
        // payloads, so this exercises bigger raft log entries than api_key.
        .register_scenario(
            scenario!("MappingCRUD")
                .set_weight(1)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(mapping_create).set_on_start())
                .register_transaction(transaction!(mapping_show))
                .register_transaction(transaction!(mapping_list))
                .register_transaction(transaction!(mapping_delete).set_on_stop()),
        )
        // Raft-backed OAuth2 client CRUD (ADR 0026 §5): oauth2-client-driver-raft.
        .register_scenario(
            scenario!("OAuth2ClientCRUD")
                .set_weight(1)?
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(oauth2_client_create).set_on_start())
                .register_transaction(transaction!(oauth2_client_show))
                .register_transaction(transaction!(oauth2_client_list))
                .register_transaction(transaction!(oauth2_client_delete).set_on_stop()),
        )
        // Read-heavy OAuth2 discovery: jwks + well-known are unauthenticated,
        // linearizable-read-policy paths (ADR 0016-v2 §3) -- the actual
        // steady-state traffic most OAuth2 relying parties generate.
        .register_scenario(
            scenario!("OAuth2Discovery")
                .set_weight(3)?
                .register_transaction(transaction!(oauth2_jwks))
                .register_transaction(transaction!(oauth2_well_known)),
        );

    attack.execute().await?;

    seed::cleanup(&host, &admin_token, &seed_state).await;

    Ok(())
}

/// Build the admin cloud config, preferring plain `OS_*` auth env vars
/// (`OS_AUTH_URL`, `OS_USERNAME`, `OS_PASSWORD`, ...) over a `clouds.yaml`
/// entry when `OS_AUTH_URL` is set, so CI/local runs don't need a clouds.yaml
/// at all. Falls back to `OS_CLOUD` (default `devstack`) looked up via
/// clouds.yaml otherwise.
fn load_cloud_config() -> CloudConfig {
    if env::var("OS_AUTH_URL").is_ok() {
        return CloudConfig::from_env().expect("cannot build cloud config from OS_* env vars");
    }
    let cfg = ConfigFile::new().expect("cannot read clouds.yaml");
    let cloud_name = env::var("OS_CLOUD").unwrap_or("devstack".to_string());
    cfg.get_cloud_config(&cloud_name)
        .expect("cannot get cloud config")
        .unwrap_or_else(|| panic!("cloud '{cloud_name}' not found in clouds.yaml"))
}

/// Authenticate via the configured OS_CLOUD/OS_* env vars and store the
/// token in session data.
pub async fn openstack_login(user: &mut GooseUser) -> TransactionResult {
    let profile = load_cloud_config();
    let session = AsyncOpenStack::new(&profile)
        .await
        .expect("cannot connect to the cloud");
    let token = session.get_auth_token().expect("no auth token in session");
    user.set_session_data(Session {
        token,
        user_id: None,
        project_id: None,
        role_id: None,
        api_key_client_id: None,
        mapping_id: None,
        oauth2_client_id: None,
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

/// Obtain an admin token using the configured OS_CLOUD/OS_* env vars.
async fn get_admin_token() -> String {
    let profile = load_cloud_config();
    let session = AsyncOpenStack::new(&profile)
        .await
        .expect("cannot authenticate");
    session.get_auth_token().expect("no auth token")
}
