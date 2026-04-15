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

use eyre::Result;
use url::Url;
use uuid::Uuid;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softtoken::SoftToken;

use openstack_keystone_webauthn::types::*;

mod common;
use common::{generate_webauthn_credential, get_state};

#[tracing_test::traced_test]
#[tokio::test]
async fn test_webauthn_register() -> Result<()> {
    let (state, _dir) = get_state(None).await?;
    let user_id = Uuid::new_v4();

    let (_ccr, reg_state) = state.extension.webauthn.start_passkey_registration(
        user_id,
        "user_name",
        "user_name",
        None,
    )?;
    state
        .extension
        .provider
        .save_user_webauthn_credential_registration_state(
            &state.core,
            &user_id.to_string(),
            &reg_state,
        )
        .await?;
    let reg_state_2 = state
        .extension
        .provider
        .get_user_webauthn_credential_registration_state(&state.core, &user_id.to_string())
        .await?
        .unwrap();
    assert_eq!(
        serde_json::to_value(&reg_state)?,
        serde_json::to_value(&reg_state_2)?
    );
    state
        .extension
        .provider
        .delete_user_webauthn_credential_registration_state(&state.core, &user_id.to_string())
        .await?;
    assert!(
        state
            .extension
            .provider
            .get_user_webauthn_credential_registration_state(&state.core, &user_id.to_string())
            .await?
            .is_none()
    );
    Ok(())
}

#[tracing_test::traced_test]
#[tokio::test]
async fn test_webauthn_auth() -> Result<()> {
    let (state, _dir) = get_state(None).await?;
    let user_id = Uuid::new_v4();

    let mut authenticator = WebauthnAuthenticator::new(SoftToken::new(true)?.0);
    let cred = generate_webauthn_credential(&state, &mut authenticator, user_id.clone())?;

    let (_ccr, auth_state) = state
        .extension
        .webauthn
        .start_passkey_authentication(&[cred.data])?;

    state
        .extension
        .provider
        .save_user_webauthn_credential_authentication_state(
            &state.core,
            &user_id.to_string(),
            &auth_state,
        )
        .await?;
    let auth_state_2 = state
        .extension
        .provider
        .get_user_webauthn_credential_authentication_state(&state.core, &user_id.to_string())
        .await?
        .unwrap();
    assert_eq!(
        serde_json::to_value(&auth_state)?,
        serde_json::to_value(&auth_state_2)?
    );
    state
        .extension
        .provider
        .delete_user_webauthn_credential_authentication_state(&state.core, &user_id.to_string())
        .await?;
    assert!(
        state
            .extension
            .provider
            .get_user_webauthn_credential_authentication_state(&state.core, &user_id.to_string())
            .await?
            .is_none()
    );
    Ok(())
}

fn compare_credential(left: &WebauthnCredential, right: &WebauthnCredential) {
    assert_eq!(left.counter, right.counter);
    assert_eq!(left.credential_id, right.credential_id);
    // Mysql is rounding the DateTime type to seconds loosing the precision and eventually even
    // altering the second. Do not compare the created_at at all.
    //assert_eq!(
    //    left.created_at.trunc_subsecs(0),
    //    right.created_at.trunc_subsecs(0)
    //);
    assert_eq!(left.description, right.description);
    assert_eq!(left.last_used_at, right.last_used_at);
    assert_eq!(left.r#type, right.r#type);
    assert_eq!(left.updated_at, right.updated_at);
    assert_eq!(left.user_id, right.user_id);
}

#[tracing_test::traced_test]
#[tokio::test]
async fn test_webauthn_credential() -> Result<()> {
    let (state, _dir) = get_state(None).await?;
    let authenticator_backend = SoftToken::new(true)?.0;
    let mut authenticator = WebauthnAuthenticator::new(authenticator_backend);
    let user_id = Uuid::new_v4();

    let mut cred1 = generate_webauthn_credential(&state, &mut authenticator, user_id.clone())?;
    let cred2 = generate_webauthn_credential(&state, &mut authenticator, user_id.clone())?;

    let res = state
        .extension
        .provider
        .create_user_webauthn_credential(&state.core, &cred1)
        .await?;
    compare_credential(&res, &cred1);
    state
        .extension
        .provider
        .create_user_webauthn_credential(&state.core, &cred2)
        .await?;

    let list = state
        .extension
        .provider
        .list_user_webauthn_credentials(&state.core, &user_id.to_string())
        .await?;
    assert_eq!(2, list.len());
    assert!(
        list.iter()
            .find(|i| i.credential_id == cred1.credential_id)
            .is_some()
    );
    assert!(
        list.iter()
            .find(|i| i.credential_id == cred2.credential_id)
            .is_some()
    );
    cred1.description = Some("new description".into());
    let res = state
        .extension
        .provider
        .update_user_webauthn_credential(&state.core, &cred1.user_id, &cred1.credential_id, &cred1)
        .await?;
    compare_credential(&cred1, &res);
    let updated_cred = state
        .extension
        .provider
        .get_user_webauthn_credential(&state.core, &cred1.user_id, &cred1.credential_id)
        .await?
        .expect("must be found");
    compare_credential(&cred1, &updated_cred);
    state
        .extension
        .provider
        .delete_user_webauthn_credential(&state.core, &cred1.user_id, &cred1.credential_id)
        .await?;
    assert!(
        state
            .extension
            .provider
            .get_user_webauthn_credential(&state.core, &cred1.user_id, &cred1.credential_id)
            .await?
            .is_none()
    );
    compare_credential(
        &state
            .extension
            .provider
            .get_user_webauthn_credential(&state.core, &cred2.user_id, &cred2.credential_id)
            .await?
            .expect("must be present"),
        &cred2,
    );
    Ok(())
}

#[tokio::test]
async fn test_webauthn_roundtrip() -> Result<()> {
    let (state, _dir) = get_state(None).await?;
    let user_id = Uuid::new_v4();
    let authenticator_backend = SoftToken::new(true)?.0;
    let origin = Url::parse("https://keystone.local")?;
    let mut authenticator = WebauthnAuthenticator::new(authenticator_backend);

    // init new cred registration
    let (ccr, reg_state) = state.extension.webauthn.start_passkey_registration(
        user_id,
        "user_name",
        "user_name",
        None,
    )?;
    // server persist the temporary state
    state
        .extension
        .provider
        .save_user_webauthn_credential_registration_state(
            &state.core,
            &user_id.to_string(),
            &reg_state,
        )
        .await?;

    // user signs request
    let reg_result = authenticator.do_registration(origin.clone(), ccr)?;
    // server reads the saved state for the user
    let reg_state_2 = state
        .extension
        .provider
        .get_user_webauthn_credential_registration_state(&state.core, &user_id.to_string())
        .await?
        .unwrap();

    // server completes the registration
    let cred = WebauthnCredential::from_passkey(
        state
            .extension
            .webauthn
            .finish_passkey_registration(&reg_result, &reg_state_2)?,
        user_id,
        Some("descr"),
    );
    // server stores registered credential for the user
    state
        .extension
        .provider
        .create_user_webauthn_credential(&state.core, &cred)
        .await?;

    // user inits authentication
    let (cca, auth_state) = state
        .extension
        .webauthn
        .start_passkey_authentication(&[cred.data])?;

    // server saves the auth state
    state
        .extension
        .provider
        .save_user_webauthn_credential_authentication_state(
            &state.core,
            &user_id.to_string(),
            &auth_state,
        )
        .await?;

    // user signs auth request
    let auth_challenge_response = authenticator.do_authentication(
        origin,
        webauthn_authenticator_rs::prelude::RequestChallengeResponse {
            public_key: cca.public_key.try_into()?,
            mediation: cca.mediation.map(Into::into),
        },
    )?;

    // server fetches auth state
    let auth_state_2 = state
        .extension
        .provider
        .get_user_webauthn_credential_authentication_state(&state.core, &user_id.to_string())
        .await?
        .unwrap();

    // server finished the authentication
    state
        .extension
        .webauthn
        .finish_passkey_authentication(&auth_challenge_response, &auth_state_2)?;

    Ok(())
}
