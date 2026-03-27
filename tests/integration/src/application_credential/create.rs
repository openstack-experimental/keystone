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
//! Test create application credential by ID functionality.

use eyre::Report;
use itertools::Itertools;
use secrecy::ExposeSecret;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone::application_credential::{
    ApplicationCredentialApi, ApplicationCredentialProviderError,
};
use openstack_keystone_core_types::application_credential::*;
use openstack_keystone_core_types::role::*;

use crate::common::get_state;
use crate::{create_domain, create_project, create_role, create_user};

#[tokio::test]
#[traced_test]
async fn test_create_basic() -> Result<(), Report> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;

    let sot = ApplicationCredentialCreate {
        access_rules: Some(vec![AccessRuleCreate {
            id: None,
            path: Some("path1".into()),
            method: Some("method".into()),
            service: Some("service".into()),
        }]),
        description: Some("description".into()),
        name: Uuid::new_v4().to_string(),
        project_id: project.id.clone(),
        roles: vec![],
        user_id: user.id.clone(),
        ..Default::default()
    };

    let cred: ApplicationCredentialCreateResponse = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(&state, sot.clone())
        .await?;

    assert!(
        !cred.secret.expose_secret().is_empty(),
        "secret is not empty"
    );
    assert_eq!(sot.name, cred.name, "name is same");
    assert_eq!(sot.description, cred.description, "description is same");
    assert_eq!(sot.project_id, cred.project_id, "project_id is same");
    assert_eq!(sot.user_id, cred.user_id, "user_id is same");
    assert!(
        cred.access_rules
            .expect("access rules are present")
            .iter()
            .map(|ar| (ar.path.clone(), ar.method.clone(), ar.service.clone()))
            .contains(&(
                Some("path1".into()),
                Some("method".into()),
                Some("service".into())
            )),
        "Requested access rule is in the response"
    );
    assert!(!cred.unrestricted, "by default not unrestricted");

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_id_reuse() -> Result<(), Report> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let sot = ApplicationCredentialCreate {
        id: Some(Uuid::new_v4().to_string()),
        name: Uuid::new_v4().to_string(),
        project_id: project.id.clone(),
        roles: vec![],
        user_id: user.id.clone(),
        ..Default::default()
    };
    let cred: ApplicationCredentialCreateResponse = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(&state, sot.clone())
        .await?;

    assert_eq!(
        sot.id.expect("id was present"),
        cred.id,
        "passed id was respected"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_secret_reuse() -> Result<(), Report> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let secret = "this is the secret".to_string();
    let cred: ApplicationCredentialCreateResponse = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &state,
            ApplicationCredentialCreate {
                name: Uuid::new_v4().to_string(),
                project_id: project.id.clone(),
                roles: vec![],
                secret: Some(secret.clone().into()),
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    assert_eq!(
        secret,
        cred.secret.expose_secret(),
        "response secret is same as in the request"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_nonexisting_role() -> Result<(), Report> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    if let Err(ApplicationCredentialProviderError::RoleNotFound(r)) = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &state,
            ApplicationCredentialCreate {
                name: Uuid::new_v4().to_string(),
                project_id: project.id.clone(),
                roles: vec![RoleRef {
                    id: "missing".into(),
                    name: None,
                    domain_id: None,
                }],
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await
    {
        assert_eq!("missing", r);
    } else {
        panic!("appcred for the missing role should not be created");
    }

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_role() -> Result<(), Report> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let role_a = create_role!(state)?;
    let user = create_user!(state, domain.id.clone())?;
    let cred = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &state,
            ApplicationCredentialCreate {
                name: Uuid::new_v4().to_string(),
                project_id: project.id.clone(),
                roles: vec![RoleRef::from(role_a.clone())],
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    assert!(
        cred.roles.iter().any(|x| x.id == role_a.id),
        "role_a is present in roles"
    );
    Ok(())
}
