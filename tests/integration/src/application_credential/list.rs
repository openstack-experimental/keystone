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

use openstack_keystone::application_credential::ApplicationCredentialApi;
use openstack_keystone_core_types::application_credential::*;

use crate::common::get_state;
use crate::{create_application_credential, create_domain, create_project, create_user};

#[tokio::test]
#[traced_test]
async fn test_list() -> Result<(), Report> {
    let (state, _) = get_state().await?;

    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let ac1 = create_application_credential!(state, user.id.clone(), project.id.clone())?;
    let ac2 = create_application_credential!(state, user.id.clone(), project.id.clone())?;

    let creds: Vec<ApplicationCredential> = state
        .provider
        .get_application_credential_provider()
        .list_application_credentials(
            &state,
            &ApplicationCredentialListParameters {
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .collect();
    assert!(creds.clone().iter().any(|ac| ac.name == ac1.name));
    assert!(creds.clone().iter().any(|ac| ac.name == ac2.name));
    let creds: Vec<ApplicationCredential> = state
        .provider
        .get_application_credential_provider()
        .list_application_credentials(
            &state,
            &ApplicationCredentialListParameters {
                user_id: "missing".into(),
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .collect();
    assert!(creds.is_empty());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_limit() -> Result<(), Report> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let mut res = Vec::new();
    for _ in 1..10 {
        res.push(create_application_credential!(
            state,
            user.id.clone(),
            project.id.clone()
        )?);
    }

    let creds: Vec<ApplicationCredential> = state
        .provider
        .get_application_credential_provider()
        .list_application_credentials(
            &state,
            &ApplicationCredentialListParameters {
                user_id: user.id.clone(),
                limit: Some(5),
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .collect();
    assert_eq!(5, creds.len(), "5 app creds returned");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_by_name() -> Result<(), Report> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let ac1 = create_application_credential!(state, user.id.clone(), project.id.clone())?;
    let mut res = Vec::new();
    for _ in 1..5 {
        res.push(create_application_credential!(
            state,
            user.id.clone(),
            project.id.clone()
        )?);
    }

    let creds: Vec<ApplicationCredential> = state
        .provider
        .get_application_credential_provider()
        .list_application_credentials(
            &state,
            &ApplicationCredentialListParameters {
                user_id: user.id.clone(),
                name: Some(ac1.name.clone()),
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .collect();
    assert_eq!(1, creds.len(), "1 app creds returned");
    assert_eq!(creds.first().expect("appcred is found").name, ac1.name);
    Ok(())
}
