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
//! Test application credential access rule CRD functionality.

use eyre::Report;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone::application_credential::ApplicationCredentialProviderError;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::application_credential::*;

use crate::common::get_state;
use crate::{create_domain, create_project, create_user};

#[tokio::test]
#[traced_test]
async fn test_access_rule_crd() -> Result<(), Report> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;
    let provider = state.provider.get_application_credential_provider();

    // Create
    let created = provider
        .create_access_rule(
            &ExecutionContext::internal(&state),
            AccessRuleCreate {
                id: None,
                path: Some("/v2.1/servers".into()),
                method: Some("POST".into()),
                service: Some("compute".into()),
                user_id: user.id.clone(),
            },
        )
        .await?;
    assert!(!created.id.is_empty(), "an id was generated");
    assert_eq!(created.path, Some("/v2.1/servers".into()));
    assert_eq!(created.method, Some("POST".into()));
    assert_eq!(created.service, Some("compute".into()));
    assert_eq!(created.user_id, user.id, "owner is exposed in the output");

    // Get
    let fetched = provider
        .get_access_rule(&ExecutionContext::internal(&state), &user.id, &created.id)
        .await?
        .expect("access rule is present");
    assert_eq!(fetched, created, "fetched rule matches the created one");

    // List
    let listed = provider
        .list_access_rules(&ExecutionContext::internal(&state), &user.id)
        .await?;
    assert!(
        listed.iter().any(|r| r.id == created.id),
        "created rule is listed"
    );

    // Delete
    provider
        .delete_access_rule(&ExecutionContext::internal(&state), &user.id, &created.id)
        .await?;
    assert!(
        provider
            .get_access_rule(&ExecutionContext::internal(&state), &user.id, &created.id)
            .await?
            .is_none(),
        "rule is gone after delete"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_delete_access_rule_not_found() -> Result<(), Report> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;

    let result = state
        .provider
        .get_application_credential_provider()
        .delete_access_rule(&ExecutionContext::internal(&state), &user.id, "missing")
        .await;

    assert!(
        matches!(
            result,
            Err(ApplicationCredentialProviderError::AccessRuleNotFound(_))
        ),
        "deleting a missing rule reports AccessRuleNotFound"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_delete_access_rule_in_use() -> Result<(), Report> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let provider = state.provider.get_application_credential_provider();

    // An access rule created together with an application credential is in use.
    let rule_id = Uuid::new_v4().to_string();
    provider
        .create_application_credential(
            &ExecutionContext::internal(&state),
            ApplicationCredentialCreate {
                access_rules: Some(vec![AccessRuleCreate {
                    id: Some(rule_id.clone()),
                    path: Some("/v2.1/servers".into()),
                    method: Some("POST".into()),
                    service: Some("compute".into()),
                    user_id: user.id.clone(),
                }]),
                name: Uuid::new_v4().to_string(),
                project_id: project.id.clone(),
                roles: vec![],
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    let result = provider
        .delete_access_rule(&ExecutionContext::internal(&state), &user.id, &rule_id)
        .await;

    assert!(
        matches!(
            result,
            Err(ApplicationCredentialProviderError::AccessRuleInUse(_))
        ),
        "a rule still attached to a credential cannot be deleted"
    );

    Ok(())
}
