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
use std::collections::BTreeSet;
use tracing_test::traced_test;
use uuid::Uuid;

use super::get_state;
use openstack_keystone::application_credential::ApplicationCredentialApi;
use openstack_keystone::application_credential::types::*;
use openstack_keystone::assignment::types::Role;

#[tokio::test]
#[traced_test]
async fn test_get() -> Result<(), Report> {
    let state = get_state().await?;

    let sot: ApplicationCredentialCreateResponse = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &state,
            ApplicationCredentialCreate {
                access_rules: Some(vec![AccessRuleCreate {
                    id: None,
                    path: Some("path1".into()),
                    method: Some("method".into()),
                    service: Some("service".into()),
                }]),
                description: Some("description".into()),
                name: Uuid::new_v4().to_string(),
                project_id: "project_a".into(),
                roles: vec![
                    Role {
                        id: "role_a".into(),
                        ..Default::default()
                    },
                    Role {
                        id: "role_b".into(),
                        ..Default::default()
                    },
                ],
                user_id: "user_a".into(),
                ..Default::default()
            },
        )
        .await?;

    let cred: ApplicationCredential = state
        .provider
        .get_application_credential_provider()
        .get_application_credential(&state, &sot.id)
        .await?
        .expect("appcred found");

    assert_eq!(sot.id, cred.id);
    assert_eq!(sot.name, cred.name);
    assert_eq!(sot.description, cred.description);
    assert_eq!(
        BTreeSet::from_iter(sot.roles.clone().into_iter().map(|role| role.id)),
        BTreeSet::from_iter(cred.roles.clone().into_iter().map(|role| role.id))
    );
    assert_eq!(
        BTreeSet::from_iter(
            sot.access_rules
                .clone()
                .expect("has rules")
                .into_iter()
                .map(|rule| (rule.path, rule.method, rule.service))
        ),
        BTreeSet::from_iter(
            cred.access_rules
                .clone()
                .expect("has rules")
                .into_iter()
                .map(|rule| (rule.path, rule.method, rule.service))
        ),
    );

    Ok(())
}
