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

use chrono::Local;
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

use crate::db::entity::webauthn_state;
use crate::error::DbContextExt;
use crate::webauthn::WebauthnError;

pub async fn create_register<U: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
    state: PasskeyRegistration,
) -> Result<(), WebauthnError> {
    let now = Local::now().naive_utc();
    let entry = webauthn_state::ActiveModel {
        user_id: Set(user_id.as_ref().to_string()),
        state: Set(serde_json::to_string(&state)?),
        r#type: Set("register".into()),
        created_at: Set(now),
    };
    let _ = entry
        .insert(db)
        .await
        .context("inserting webauthn registration state record")?;

    Ok(())
}

pub async fn create_auth<U: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
    state: PasskeyAuthentication,
) -> Result<(), WebauthnError> {
    let now = Local::now().naive_utc();
    let entry = webauthn_state::ActiveModel {
        user_id: Set(user_id.as_ref().to_string()),
        state: Set(serde_json::to_string(&state)?),
        r#type: Set("auth".into()),
        created_at: Set(now),
    };
    let _ = entry
        .insert(db)
        .await
        .context("inserting webauthn auth state record")?;
    Ok(())
}

#[cfg(test)]
mod tests {}
