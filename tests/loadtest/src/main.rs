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

use goose::prelude::*;
use std::env;

use openstack_sdk::{AsyncOpenStack, config::ConfigFile};

mod v3;

use crate::v3::auth::validate as validate_token;
use crate::v3::user::list as user_list;

struct Session {
    token: String,
}

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    GooseAttack::initialize()?
        .register_scenario(
            scenario!("ListUsers")
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(user_list)),
        )
        .register_scenario(
            scenario!("ValidateToken")
                .register_transaction(transaction!(openstack_login).set_on_start())
                .register_transaction(transaction!(validate_token)),
        )
        .execute()
        .await?;

    Ok(())
}

/// Login to OpenStack ($OS_CLOUD) and save the token in the session.
async fn openstack_login(user: &mut GooseUser) -> TransactionResult {
    let cfg = ConfigFile::new().unwrap();
    // Get connection config from clouds.yaml/secure.yaml
    let profile = cfg
        .get_cloud_config(env::var("OS_CLOUD").ok().unwrap_or("devstack".to_string()))
        .unwrap()
        .unwrap();
    // Establish connection
    let session = AsyncOpenStack::new(&profile)
        .await
        .expect("cannot connect to the cloud");
    if let Some(token) = session.get_auth_token() {
        user.set_session_data(Session { token });
    }

    Ok(())
}
