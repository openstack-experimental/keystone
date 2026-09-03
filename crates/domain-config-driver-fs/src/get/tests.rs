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

use std::collections::HashMap;

use serde_json::{Value, json};

use openstack_keystone_core_types::domain_config::DomainConfig;

use super::*;

/// A store holding one domain built from a request-shaped body.
fn store_with(domain_name: &str, config: Value) -> DomainConfigStore {
    let config = DomainConfig::from_value(config).expect("a valid domain configuration");
    DomainConfigStore::from_map(HashMap::from([(domain_name.to_string(), config)]))
}

#[test]
fn get_config_returns_the_whole_configuration_including_sensitive_options() {
    let store = store_with(
        "Acme",
        json!({"ldap": {"url": "ldap://host", "password": "s3cr3t"}}),
    );

    let config = get_config(&store, "Acme")
        .unwrap()
        .expect("Acme is configured");
    let ldap = config.group(DomainConfigGroupName::Ldap).unwrap();
    assert_eq!(ldap.get("url"), Some(&json!("ldap://host")));
    assert_eq!(ldap.get("password"), Some(&json!("s3cr3t")));

    assert!(get_config(&store, "other").unwrap().is_none());
}

#[test]
fn get_group_filters_sensitive_options() {
    let store = store_with(
        "Acme",
        json!({"ldap": {"url": "ldap://host", "password": "s3cr3t"}}),
    );

    let group = get_group(&store, "Acme", DomainConfigGroupName::Ldap)
        .unwrap()
        .expect("the ldap group has a readable option");
    assert_eq!(group.name(), DomainConfigGroupName::Ldap);
    assert_eq!(group.get("url"), Some(&json!("ldap://host")));
    assert_eq!(group.get("password"), None);
}

#[test]
fn get_group_is_none_when_only_a_sensitive_option_is_set() {
    let store = store_with("Acme", json!({"ldap": {"password": "s3cr3t"}}));

    assert!(
        get_group(&store, "Acme", DomainConfigGroupName::Ldap)
            .unwrap()
            .is_none()
    );
}

#[test]
fn get_group_is_none_for_an_absent_group_or_domain() {
    let store = store_with("Acme", json!({"identity": {"driver": "ldap"}}));

    assert!(
        get_group(&store, "Acme", DomainConfigGroupName::Ldap)
            .unwrap()
            .is_none()
    );
    assert!(
        get_group(&store, "other", DomainConfigGroupName::Identity)
            .unwrap()
            .is_none()
    );
}

#[test]
fn get_option_never_returns_a_sensitive_option() {
    let store = store_with("Acme", json!({"ldap": {"password": "s3cr3t"}}));

    // Sensitive: `None` without consulting the store at all.
    assert!(
        get_option(&store, "Acme", DomainConfigGroupName::Ldap, "password")
            .unwrap()
            .is_none()
    );
    assert!(
        get_option(&store, "missing", DomainConfigGroupName::Ldap, "password")
            .unwrap()
            .is_none()
    );
}

#[test]
fn get_option_returns_a_present_readable_option() {
    let store = store_with("Acme", json!({"ldap": {"url": "ldap://host"}}));

    let option = get_option(&store, "Acme", DomainConfigGroupName::Ldap, "url")
        .unwrap()
        .expect("url is set");
    assert_eq!(option.group, DomainConfigGroupName::Ldap);
    assert_eq!(option.option, "url");
    assert!(!option.sensitive());
    assert_eq!(Value::from(option.value.clone()), json!("ldap://host"));

    assert!(
        get_option(&store, "Acme", DomainConfigGroupName::Ldap, "suffix")
            .unwrap()
            .is_none()
    );
    assert!(
        get_option(&store, "other", DomainConfigGroupName::Ldap, "url")
            .unwrap()
            .is_none()
    );
}
