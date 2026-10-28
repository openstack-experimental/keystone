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

//! Trust churn: the admin delegates its project role to a throwaway trustee;
//! the trust is read, listed by trustor and deleted. (Trust-scoped
//! authentication is not served by keystone-rs yet, so the trustee never
//! exchanges the trust for a token.)

use goose::prelude::*;
use serde_json::json;

use crate::v3::util::{Undo, admin_token, call, create_user};

pub async fn cycle(user: &mut GooseUser) -> TransactionResult {
    let mut undo = Undo::default();
    let res = run(user, &mut undo).await;
    undo.run(user).await;
    res
}

async fn run(user: &mut GooseUser, undo: &mut Undo) -> TransactionResult {
    let token = admin_token(user);

    // Who is the admin, and which project/role does its token carry.
    let validate = user
        .get_request_builder(&GooseMethod::Get, "/v3/auth/tokens")?
        .header("x-auth-token", &token)
        .header("x-subject-token", &token);
    let mut goose = user
        .request(
            GooseRequest::builder()
                .name("GET /v3/auth/tokens (trustor)")
                .set_request_builder(validate)
                .build(),
        )
        .await?;
    let info: serde_json::Value = match goose.response {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or_default(),
        _ => return user.set_failure("cannot inspect admin token", &mut goose.request, None, None),
    };
    let (Some(trustor), Some(project), Some(role)) = (
        info["token"]["user"]["id"].as_str(),
        info["token"]["project"]["id"].as_str(),
        info["token"]["roles"][0]["id"].as_str(),
    ) else {
        return Ok(());
    };

    let Some((trustee, _)) = create_user(user, undo).await? else {
        return Ok(());
    };
    let body = json!({"trust": {
        "trustor_user_id": trustor,
        "trustee_user_id": trustee,
        "project_id": project,
        "impersonation": false,
        "roles": [{"id": role}],
    }});
    let Some(created) = call(
        user,
        GooseMethod::Post,
        "/v3/OS-TRUST/trusts",
        "POST /v3/OS-TRUST/trusts",
        Some(&body),
        Some(&token),
    )
    .await?
    else {
        return Ok(());
    };
    let Some(trust_id) = created.body["trust"]["id"].as_str().map(str::to_owned) else {
        return Ok(());
    };
    undo.push(
        format!("/v3/OS-TRUST/trusts/{trust_id}"),
        "DELETE /v3/OS-TRUST/trusts/:id",
    );

    call(
        user,
        GooseMethod::Get,
        &format!("/v3/OS-TRUST/trusts/{trust_id}"),
        "GET /v3/OS-TRUST/trusts/:id",
        None,
        Some(&token),
    )
    .await?;
    call(
        user,
        GooseMethod::Get,
        &format!("/v3/OS-TRUST/trusts?trustor_user_id={trustor}"),
        "GET /v3/OS-TRUST/trusts (by trustor)",
        None,
        Some(&token),
    )
    .await?;

    Ok(())
}
