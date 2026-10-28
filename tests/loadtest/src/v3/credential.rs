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

//! Credential churn with varying blob sizes (100 B - 8 KiB): create, show,
//! update, list and delete, owned by a throwaway user.

use goose::prelude::*;
use serde_json::json;
use uuid::Uuid;

use crate::v3::user::auth_project_id;
use crate::v3::util::{Undo, admin_token, call, create, create_user};

pub async fn cycle(user: &mut GooseUser) -> TransactionResult {
    let mut undo = Undo::default();
    let res = run(user, &mut undo).await;
    undo.run(user).await;
    res
}

/// EC2 blob with a random size. The access key is the credential identity
/// (its id is derived from it), so updates must keep it.
fn blob(access: &str) -> String {
    let len = 100 + fastrand::usize(..7900);
    json!({
        "access": access,
        "secret": "x".repeat(len),
    })
    .to_string()
}

async fn run(user: &mut GooseUser, undo: &mut Undo) -> TransactionResult {
    let Some(project_id) = auth_project_id() else {
        return Ok(());
    };
    let token = admin_token(user);
    let access = Uuid::new_v4().as_simple().to_string();
    let Some((user_id, _)) = create_user(user, undo).await? else {
        return Ok(());
    };
    let Some(cred_id) = create(
        user,
        undo,
        "credentials",
        "credential",
        json!({"credential": {
            "user_id": user_id,
            "project_id": project_id,
            "type": "ec2",
            "blob": blob(&access),
        }}),
        "POST /v3/credentials",
        "DELETE /v3/credentials/:id",
    )
    .await?
    else {
        return Ok(());
    };
    let path = format!("/v3/credentials/{cred_id}");
    call(
        user,
        GooseMethod::Get,
        &path,
        "GET /v3/credentials/:id",
        None,
        Some(&token),
    )
    .await?;
    let patch = json!({"credential": {"blob": blob(&access)}});
    call(
        user,
        GooseMethod::Patch,
        &path,
        "PATCH /v3/credentials/:id",
        Some(&patch),
        Some(&token),
    )
    .await?;
    call(
        user,
        GooseMethod::Get,
        &format!("/v3/credentials?user_id={user_id}"),
        "GET /v3/credentials (by user)",
        None,
        Some(&token),
    )
    .await?;
    Ok(())
}
