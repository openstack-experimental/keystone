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

use serde_json::{Value, json};

use openstack_keystone_core_types::domain_config::DomainConfigGroupName;

use super::*;
use crate::domain_config::backend::MockDomainConfigBackend;
use crate::tests::get_mocked_state;

/// A `DomainConfig` from a request-shaped body.
fn config(body: Value) -> DomainConfig {
    DomainConfig::from_value(body).expect("a valid domain configuration")
}

/// A backend whose `get_domain_config` always answers `answer`.
fn source(
    answer: Result<Option<DomainConfig>, DomainConfigProviderError>,
) -> Arc<dyn DomainConfigBackend> {
    let mut mock = MockDomainConfigBackend::new();
    mock.expect_get_domain_config().returning(move |_, _| {
        answer
            .as_ref()
            .map(|maybe| maybe.clone())
            .map_err(|err| DomainConfigProviderError::Driver(err.to_string()))
    });
    Arc::new(mock)
}

/// An `ldap` option of a resolved configuration.
fn ldap<'a>(resolved: &'a DomainConfig, option: &str) -> Option<&'a Value> {
    resolved
        .group(DomainConfigGroupName::Ldap)
        .and_then(|group| group.get(option))
}

#[tokio::test]
async fn no_source_resolves_to_the_empty_configuration() {
    let state = get_mocked_state(None, None).await;
    let resolver = DomainConfigResolver {
        file: None,
        database: None,
    };
    assert!(
        resolver
            .effective_config(&state, "d1")
            .await
            .expect("resolvable")
            .is_empty()
    );
}

#[tokio::test]
async fn disabled_resolves_to_the_empty_configuration() {
    let state = get_mocked_state(None, None).await;
    assert!(
        DomainConfigResolver::disabled()
            .effective_config(&state, "d1")
            .await
            .expect("resolvable")
            .is_empty()
    );
}

#[tokio::test]
async fn the_file_source_alone_is_returned_verbatim() {
    let state = get_mocked_state(None, None).await;
    let resolver = DomainConfigResolver {
        file: Some(source(Ok(Some(config(
            json!({"ldap": {"url": "ldap://file"}}),
        ))))),
        database: None,
    };
    let resolved = resolver
        .effective_config(&state, "d1")
        .await
        .expect("resolvable");
    assert_eq!(ldap(&resolved, "url"), Some(&json!("ldap://file")));
}

#[tokio::test]
async fn the_database_source_alone_is_returned_verbatim() {
    let state = get_mocked_state(None, None).await;
    let resolver = DomainConfigResolver {
        file: None,
        database: Some(source(Ok(Some(config(
            json!({"ldap": {"url": "ldap://db"}}),
        ))))),
    };
    let resolved = resolver
        .effective_config(&state, "d1")
        .await
        .expect("resolvable");
    assert_eq!(ldap(&resolved, "url"), Some(&json!("ldap://db")));
}

#[tokio::test]
async fn the_database_overrides_the_file_option_by_option() {
    let state = get_mocked_state(None, None).await;
    let resolver = DomainConfigResolver {
        file: Some(source(Ok(Some(config(
            json!({"ldap": {"url": "ldap://file", "suffix": "dc=file"}}),
        ))))),
        database: Some(source(Ok(Some(config(
            json!({"ldap": {"url": "ldap://db"}}),
        ))))),
    };
    let resolved = resolver
        .effective_config(&state, "d1")
        .await
        .expect("resolvable");
    assert_eq!(
        ldap(&resolved, "url"),
        Some(&json!("ldap://db")),
        "the database wins the shared option"
    );
    assert_eq!(
        ldap(&resolved, "suffix"),
        Some(&json!("dc=file")),
        "the file-only option survives"
    );
}

#[tokio::test]
async fn a_source_without_a_configuration_contributes_nothing() {
    let state = get_mocked_state(None, None).await;
    let resolver = DomainConfigResolver {
        file: Some(source(Ok(None))),
        database: Some(source(Ok(Some(config(
            json!({"ldap": {"url": "ldap://db"}}),
        ))))),
    };
    let resolved = resolver
        .effective_config(&state, "d1")
        .await
        .expect("resolvable");
    assert_eq!(ldap(&resolved, "url"), Some(&json!("ldap://db")));
}

#[tokio::test]
async fn an_error_from_a_source_propagates() {
    let state = get_mocked_state(None, None).await;
    let resolver = DomainConfigResolver {
        file: Some(source(Err(DomainConfigProviderError::Driver(
            "boom".to_string(),
        )))),
        database: None,
    };
    assert!(resolver.effective_config(&state, "d1").await.is_err());
}
