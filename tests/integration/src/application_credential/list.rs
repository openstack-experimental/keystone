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
//! Test list application credentials functionality.

use eyre::Report;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone::application_credential::ApplicationCredentialApi;
use openstack_keystone::application_credential::types::*;

use super::{create_ac, get_state};

#[tokio::test]
#[traced_test]
async fn test_list() -> Result<(), Report> {
    let state = get_state().await?;
    let ac1 = Uuid::new_v4().to_string();
    let ac2 = Uuid::new_v4().to_string();
    create_ac(&state, Some(&ac1)).await?;
    create_ac(&state, Some(&ac2)).await?;

    let params = ApplicationCredentialListParameters {
        user_id: "user_a".into(),
        ..Default::default()
    };
    let creds: Vec<ApplicationCredential> = state
        .provider
        .get_application_credential_provider()
        .list_application_credentials(&state, &params)
        .await?
        .into_iter()
        .collect();
    assert!(creds.clone().iter().any(|ac| ac.name == ac1));
    assert!(creds.clone().iter().any(|ac| ac.name == ac2));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_limit() -> Result<(), Report> {
    let state = get_state().await?;
    for _ in 1..10 {
        create_ac(&state, None::<String>).await?;
    }

    let params = ApplicationCredentialListParameters {
        user_id: "user_a".into(),
        limit: Some(5),
        ..Default::default()
    };
    let creds: Vec<ApplicationCredential> = state
        .provider
        .get_application_credential_provider()
        .list_application_credentials(&state, &params)
        .await?
        .into_iter()
        .collect();
    assert_eq!(5, creds.len(), "5 app creds returned");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_by_name() -> Result<(), Report> {
    let state = get_state().await?;
    let ac1 = Uuid::new_v4().to_string();
    create_ac(&state, Some(ac1.clone())).await?;
    for _ in 1..5 {
        create_ac(&state, None::<String>).await?;
    }

    let params = ApplicationCredentialListParameters {
        user_id: "user_a".into(),
        name: Some(ac1.clone()),
        ..Default::default()
    };
    let creds: Vec<ApplicationCredential> = state
        .provider
        .get_application_credential_provider()
        .list_application_credentials(&state, &params)
        .await?
        .into_iter()
        .collect();
    assert_eq!(1, creds.len(), "1 app creds returned");
    assert_eq!(creds.first().expect("appcred is found").name, ac1);
    Ok(())
}
