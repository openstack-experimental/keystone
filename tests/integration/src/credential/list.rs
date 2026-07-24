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
//! Test credential listing and the driver-level `user_id`/`type` filters
//! (ADR 0019 §2, §3 — `list_credentials_for_user` backs both the TOTP auth
//! pipeline and the OS-EC2 listing endpoint).

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::credential::*;

use crate::credential::{create_credential, get_state};
use crate::{create_domain, create_user};

#[tokio::test]
#[traced_test]
async fn test_list_filters_by_user_and_type() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user_a = create_user!(state, domain.id.clone())?;
    let user_b = create_user!(state, domain.id.clone())?;

    let a_totp = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"seed":"AAAA"}"#.into(),
            r#type: "totp".into(),
            user_id: Some(user_a.id.clone()),
            ..Default::default()
        },
    )
    .await?;
    let a_custom = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"x":"y"}"#.into(),
            r#type: "custom".into(),
            user_id: Some(user_a.id.clone()),
            ..Default::default()
        },
    )
    .await?;
    let _b_totp = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"seed":"BBBB"}"#.into(),
            r#type: "totp".into(),
            user_id: Some(user_b.id.clone()),
            ..Default::default()
        },
    )
    .await?;

    // All of user_a's credentials.
    let user_a_creds = state
        .provider
        .get_credential_provider()
        .list_credentials(
            &ExecutionContext::internal(&state),
            &CredentialListParameters {
                user_id: Some(user_a.id.clone()),
                r#type: None,
                pagination: Default::default(),
            },
        )
        .await?;
    let user_a_ids: Vec<&str> = user_a_creds.iter().map(|c| c.id.as_str()).collect();
    assert!(user_a_ids.contains(&a_totp.id.as_str()));
    assert!(user_a_ids.contains(&a_custom.id.as_str()));
    assert_eq!(user_a_creds.len(), 2);

    // user_a's totp credentials only.
    let user_a_totp = state
        .provider
        .get_credential_provider()
        .list_credentials(
            &ExecutionContext::internal(&state),
            &CredentialListParameters {
                user_id: Some(user_a.id.clone()),
                r#type: Some("totp".into()),
                pagination: Default::default(),
            },
        )
        .await?;
    assert_eq!(user_a_totp.len(), 1);
    assert_eq!(user_a_totp[0].id, a_totp.id);

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_credentials_for_user() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;

    let totp = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"seed":"AAAA"}"#.into(),
            r#type: "totp".into(),
            user_id: Some(user.id.clone()),
            ..Default::default()
        },
    )
    .await?;
    let _custom = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"x":"y"}"#.into(),
            r#type: "custom".into(),
            user_id: Some(user.id.clone()),
            ..Default::default()
        },
    )
    .await?;

    // Used by the TOTP auth plugin: list_credentials_for_user(user_id,
    // type='totp').
    let totp_creds = state
        .provider
        .get_credential_provider()
        .list_credentials_for_user(&ExecutionContext::internal(&state), &user.id, Some("totp"))
        .await?;
    assert_eq!(totp_creds.len(), 1);
    assert_eq!(totp_creds[0].id, totp.id);

    // No type filter: all of the user's credentials.
    let all_creds = state
        .provider
        .get_credential_provider()
        .list_credentials_for_user(&ExecutionContext::internal(&state), &user.id, None)
        .await?;
    assert_eq!(all_creds.len(), 2);

    Ok(())
}
