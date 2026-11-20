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

//! `POST /v3/s3tokens`: validate SigV2-style (HMAC-SHA1) and SigV4 signed S3
//! requests against an EC2 credential owned by a throwaway user, plus one
//! bad-signature request that must be rejected with 401.

use base64::{Engine as _, engine::general_purpose};
use goose::prelude::*;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::Sha256;
use uuid::Uuid;

use crate::v3::role_assignment::auth_role_id;
use crate::v3::user::auth_project_id;
use crate::v3::util::{Undo, admin_token, call, create, create_user};

pub async fn cycle(user: &mut GooseUser) -> TransactionResult {
    let mut undo = Undo::default();
    let res = run(user, &mut undo).await;
    undo.run(user).await;
    res
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    // HMAC accepts keys of any length, so construction cannot fail.
    <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map(|mut mac| {
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        })
        .unwrap_or_default()
}

/// Independent SigV2-style signature: base64(HMAC-SHA1(secret, sts)).
fn sign_v1(secret: &str, sts: &str) -> String {
    // HMAC accepts keys of any length, so construction cannot fail.
    <Hmac<Sha1> as Mac>::new_from_slice(secret.as_bytes())
        .map(|mut mac| {
            mac.update(sts.as_bytes());
            general_purpose::STANDARD.encode(mac.finalize().into_bytes())
        })
        .unwrap_or_default()
}

/// Independent SigV4 signature for the 4-line string-to-sign.
fn sign_v4(secret: &str, date: &str, region: &str, sts: &str) -> String {
    let k = hmac256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k = hmac256(&k, region.as_bytes());
    let k = hmac256(&k, b"s3");
    let k = hmac256(&k, b"aws4_request");
    hex(&hmac256(&k, sts.as_bytes()))
}

fn body(access: &str, signature: &str, sts: &str) -> Value {
    json!({"credentials": {
        "access": access,
        "signature": signature,
        "token": general_purpose::URL_SAFE.encode(sts),
    }})
}

async fn run(user: &mut GooseUser, undo: &mut Undo) -> TransactionResult {
    let Some(project_id) = auth_project_id() else {
        return Ok(());
    };
    let token = admin_token(user);
    let access = Uuid::new_v4().as_simple().to_string();
    let secret = Uuid::new_v4().as_simple().to_string();
    let Some((user_id, _)) = create_user(user, undo).await? else {
        return Ok(());
    };
    // The credential owner needs a role on the project, otherwise the
    // signature check is rejected with ActorHasNoRolesOnTarget (401).
    if let Some(role_id) = auth_role_id() {
        let path = format!("/v3/projects/{project_id}/users/{user_id}/roles/{role_id}");
        if call(
            user,
            GooseMethod::Put,
            &path,
            "PUT /v3/projects/:id/users/:id/roles/:id (s3tokens)",
            None,
            Some(&token),
        )
        .await?
        .is_some()
        {
            undo.push(
                path,
                "DELETE /v3/projects/:id/users/:id/roles/:id (s3tokens)",
            );
        }
    }
    let Some(_) = create(
        user,
        undo,
        "credentials",
        "credential",
        json!({"credential": {
            "user_id": user_id,
            "project_id": project_id,
            "type": "ec2",
            "blob": json!({"access": access, "secret": secret}).to_string(),
        }}),
        "POST /v3/credentials",
        "DELETE /v3/credentials/:id",
    )
    .await?
    else {
        return Ok(());
    };

    let now = chrono::Utc::now();
    let v1_sts = format!("GET\n\n\n{}\n/bucket/key", now.timestamp());
    let v1 = body(&access, &sign_v1(&secret, &v1_sts), &v1_sts);
    call(
        user,
        GooseMethod::Post,
        "/v3/s3tokens",
        "POST /v3/s3tokens (v1)",
        Some(&v1),
        Some(&token),
    )
    .await?;

    let date = now.format("%Y%m%d").to_string();
    let v4_sts = format!(
        "AWS4-HMAC-SHA256\n{}\n{date}/RegionOne/s3/aws4_request\ndeadbeef",
        now.format("%Y%m%dT%H%M%SZ")
    );
    let v4 = body(
        &access,
        &sign_v4(&secret, &date, "RegionOne", &v4_sts),
        &v4_sts,
    );
    call(
        user,
        GooseMethod::Post,
        "/v3/s3tokens",
        "POST /v3/s3tokens (SigV4)",
        Some(&v4),
        Some(&token),
    )
    .await?;

    // Wrong signature: 401 is the expected outcome.
    let bad = body(&access, &sign_v1("wrong-secret", &v1_sts), &v1_sts);
    let name = "POST /v3/s3tokens (bad signature)";
    let req = user
        .get_request_builder(&GooseMethod::Post, "/v3/s3tokens")?
        .header("x-auth-token", &token)
        .json(&bad);
    let mut goose = user
        .request(
            GooseRequest::builder()
                .name(name)
                .set_request_builder(req)
                .build(),
        )
        .await?;
    match goose.response {
        Ok(r) if r.status() == 401 => user.set_success(&mut goose.request)?,
        Ok(r) => user.set_failure(
            &format!("{name} returned {} instead of 401", r.status()),
            &mut goose.request,
            None,
            None,
        )?,
        Err(e) => user.set_failure(
            &format!("{name} failed: {e}"),
            &mut goose.request,
            None,
            None,
        )?,
    }
    Ok(())
}

/// Credential of one virtual user of the `S3TokensHot` scenario.
#[derive(Clone)]
pub struct HotCred {
    access: String,
    secret: String,
    user_id: String,
    credential_id: String,
}

/// on_start: user, role on the project and EC2 credential, created once.
pub async fn hot_setup(user: &mut GooseUser) -> TransactionResult {
    let (Some(project_id), Some(role_id)) = (auth_project_id(), auth_role_id()) else {
        return Ok(());
    };
    let token = admin_token(user);
    let access = Uuid::new_v4().as_simple().to_string();
    let secret = Uuid::new_v4().as_simple().to_string();
    // The users are removed in hot_teardown, not by the throwaway `Undo`.
    let mut undo = Undo::default();
    let Some((user_id, _)) = create_user(user, &mut undo).await? else {
        return Ok(());
    };
    let path = format!("/v3/projects/{project_id}/users/{user_id}/roles/{role_id}");
    call(
        user,
        GooseMethod::Put,
        &path,
        "PUT /v3/projects/:id/users/:id/roles/:id (s3tokens)",
        None,
        Some(&token),
    )
    .await?;
    // A server without HTTP keep-alive (uwsgi behind `--http-socket`) makes
    // the first request on a reused connection fail on the client side, so
    // retry a few times.
    let mut credential_id = None;
    for _ in 0..5 {
        let mut cred_undo = Undo::default();
        credential_id = create(
            user,
            &mut cred_undo,
            "credentials",
            "credential",
            json!({"credential": {
                "user_id": user_id,
                "project_id": project_id,
                "type": "ec2",
                "blob": json!({"access": access, "secret": secret}).to_string(),
            }}),
            "POST /v3/credentials",
            "DELETE /v3/credentials/:id",
        )
        .await?;
        if credential_id.is_some() {
            break;
        }
    }
    let Some(credential_id) = credential_id else {
        return Ok(());
    };
    user.get_session_data_unchecked_mut::<crate::Session>()
        .s3_hot = Some(HotCred {
        access,
        secret,
        user_id,
        credential_id,
    });
    Ok(())
}

/// on_stop: remove the credential and the user.
pub async fn hot_teardown(user: &mut GooseUser) -> TransactionResult {
    let Some(cred) = user
        .get_session_data_unchecked_mut::<crate::Session>()
        .s3_hot
        .take()
    else {
        return Ok(());
    };
    let token = admin_token(user);
    for (path, name) in [
        (
            format!("/v3/credentials/{}", cred.credential_id),
            "DELETE /v3/credentials/:id",
        ),
        (
            format!("/v3/users/{}", cred.user_id),
            "DELETE /v3/users/:id (churn)",
        ),
    ] {
        let _ = call(user, GooseMethod::Delete, &path, name, None, Some(&token)).await;
    }
    Ok(())
}

/// One SigV2 (v1) and one SigV4 validation, nothing else.
pub async fn hot_cycle(user: &mut GooseUser) -> TransactionResult {
    let Some(cred) = user
        .get_session_data_unchecked::<crate::Session>()
        .s3_hot
        .clone()
    else {
        // Setup failed; do not spin.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        return Ok(());
    };
    let token = admin_token(user);
    let now = chrono::Utc::now();
    let v1_sts = format!("GET\n\n\n{}\n/bucket/key", now.timestamp());
    let v1 = body(&cred.access, &sign_v1(&cred.secret, &v1_sts), &v1_sts);
    call(
        user,
        GooseMethod::Post,
        "/v3/s3tokens",
        "POST /v3/s3tokens (v1)",
        Some(&v1),
        Some(&token),
    )
    .await?;
    let date = now.format("%Y%m%d").to_string();
    let v4_sts = format!(
        "AWS4-HMAC-SHA256\n{}\n{date}/RegionOne/s3/aws4_request\ndeadbeef",
        now.format("%Y%m%dT%H%M%SZ")
    );
    let v4 = body(
        &cred.access,
        &sign_v4(&cred.secret, &date, "RegionOne", &v4_sts),
        &v4_sts,
    );
    call(
        user,
        GooseMethod::Post,
        "/v3/s3tokens",
        "POST /v3/s3tokens (SigV4)",
        Some(&v4),
        Some(&token),
    )
    .await?;
    Ok(())
}
