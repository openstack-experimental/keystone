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
//! # `UserListParameters`/`GroupListParameters` to LDAP filter translation (ADR-0027 §5).
//!
//! There is no generic Hints/comparator abstraction in this codebase (unlike
//! Python Keystone's LDAP driver): `UserListParameters` and
//! `GroupListParameters` each carry a small, fixed set of `Option` fields, so
//! translation is a direct, total function of those fields rather than a
//! general filter-comparator engine.
use openstack_keystone_config::LdapProvider;
use openstack_keystone_core_types::identity::{GroupListParameters, UserListParameters, UserType};

/// Outcome of translating list parameters into an LDAP query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListDecision {
    /// Run a subtree search with this filter string.
    Query(String),
    /// The parameters can never match anything in this backend (e.g. a
    /// `domain_id` other than the configured default, or a `user_type` that
    /// LDAP never produces) — skip the directory round trip entirely.
    EmptyResult,
}

/// Escape an LDAP filter value per RFC 4515, preventing filter injection.
pub fn escape_filter_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'*' => out.push_str("\\2a"),
            b'(' => out.push_str("\\28"),
            b')' => out.push_str("\\29"),
            b'\\' => out.push_str("\\5c"),
            0 => out.push_str("\\00"),
            _ => out.push(byte as char),
        }
    }
    out
}

/// `domain_id` short-circuit shared by user and group listing: LDAP is not
/// domain-aware, so a request scoped to any domain other than the
/// configured default can never match.
fn domain_matches(domain_id: &Option<String>, default_domain_id: &str) -> bool {
    match domain_id {
        Some(id) => id == default_domain_id,
        None => true,
    }
}

/// Translate [`UserListParameters`] into an LDAP filter, or a short-circuit
/// decision when the parameters can never match an LDAP user.
pub fn user_list_filter(
    cfg: &LdapProvider,
    default_domain_id: &str,
    params: &UserListParameters,
) -> ListDecision {
    if !domain_matches(&params.domain_id, default_domain_id) {
        return ListDecision::EmptyResult;
    }
    // LDAP users are always non-local, non-federated, non-service-account:
    // a single flat directory namespace with no local password/federation
    // tables (ADR-0027 §11).
    if matches!(
        params.user_type,
        Some(UserType::Local) | Some(UserType::Federated) | Some(UserType::ServiceAccount)
    ) {
        return ListDecision::EmptyResult;
    }

    let mut clauses = vec![
        format!("(objectClass={})", cfg.user_objectclass),
        format!("({}=*)", cfg.user_id_attribute),
    ];
    if let Some(filter) = &cfg.user_filter {
        clauses.push(filter.clone());
    }
    if let Some(name) = &params.name {
        clauses.push(format!(
            "({}={})",
            cfg.user_name_attribute,
            escape_filter_value(name)
        ));
    }
    if let Some(unique_id) = &params.unique_id {
        clauses.push(format!(
            "({}={})",
            cfg.user_id_attribute,
            escape_filter_value(unique_id)
        ));
    }
    ListDecision::Query(format!("(&{})", clauses.join("")))
}

/// Translate [`GroupListParameters`] into an LDAP filter, or a short-circuit
/// decision when the parameters can never match an LDAP group.
pub fn group_list_filter(
    cfg: &LdapProvider,
    default_domain_id: &str,
    params: &GroupListParameters,
) -> ListDecision {
    if !domain_matches(&params.domain_id, default_domain_id) {
        return ListDecision::EmptyResult;
    }

    let mut clauses = vec![
        format!("(objectClass={})", cfg.group_objectclass),
        format!("({}=*)", cfg.group_id_attribute),
    ];
    if let Some(filter) = &cfg.group_filter {
        clauses.push(filter.clone());
    }
    if let Some(name) = &params.name {
        clauses.push(format!(
            "({}={})",
            cfg.group_name_attribute,
            escape_filter_value(name)
        ));
    }
    ListDecision::Query(format!("(&{})", clauses.join("")))
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::identity::{
        GroupListParametersBuilder, UserListParametersBuilder,
    };

    use super::*;

    fn cfg() -> LdapProvider {
        LdapProvider::default()
    }

    #[test]
    fn test_escape_filter_value_escapes_all_metacharacters() {
        assert_eq!(
            escape_filter_value("a*b(c)d\\e\0f"),
            "a\\2ab\\28c\\29d\\5ce\\00f"
        );
    }

    #[test]
    fn test_escape_filter_value_passthrough_for_plain_values() {
        assert_eq!(escape_filter_value("jdoe"), "jdoe");
    }

    #[test]
    fn test_user_list_filter_defaults_to_objectclass_only() {
        let params = UserListParametersBuilder::default().build().unwrap();
        match user_list_filter(&cfg(), "default", &params) {
            ListDecision::Query(f) => assert_eq!(f, "(&(objectClass=inetOrgPerson)(cn=*))"),
            ListDecision::EmptyResult => panic!("expected a query"),
        }
    }

    #[test]
    fn test_user_list_filter_by_name_and_unique_id() {
        let params = UserListParametersBuilder::default()
            .name(Some("j*doe".to_string()))
            .unique_id(Some("uid-1".to_string()))
            .build()
            .unwrap();
        match user_list_filter(&cfg(), "default", &params) {
            ListDecision::Query(f) => {
                assert_eq!(
                    f,
                    "(&(objectClass=inetOrgPerson)(cn=*)(sn=j\\2adoe)(cn=uid-1))"
                )
            }
            ListDecision::EmptyResult => panic!("expected a query"),
        }
    }

    #[test]
    fn test_user_list_filter_includes_configured_user_filter() {
        let mut c = cfg();
        c.user_filter = Some("(mail=*@example.com)".into());
        let params = UserListParametersBuilder::default().build().unwrap();
        match user_list_filter(&c, "default", &params) {
            ListDecision::Query(f) => {
                assert_eq!(
                    f,
                    "(&(objectClass=inetOrgPerson)(cn=*)(mail=*@example.com))"
                )
            }
            ListDecision::EmptyResult => panic!("expected a query"),
        }
    }

    #[test]
    fn test_user_list_filter_domain_mismatch_short_circuits() {
        let params = UserListParametersBuilder::default()
            .domain_id(Some("other-domain".to_string()))
            .build()
            .unwrap();
        assert_eq!(
            user_list_filter(&cfg(), "default", &params),
            ListDecision::EmptyResult
        );
    }

    #[test]
    fn test_user_list_filter_matching_domain_still_queries() {
        let params = UserListParametersBuilder::default()
            .domain_id(Some("default".to_string()))
            .build()
            .unwrap();
        assert!(matches!(
            user_list_filter(&cfg(), "default", &params),
            ListDecision::Query(_)
        ));
    }

    #[test]
    fn test_user_list_filter_local_federated_service_account_short_circuit() {
        for user_type in [
            UserType::Local,
            UserType::Federated,
            UserType::ServiceAccount,
        ] {
            let params = UserListParametersBuilder::default()
                .user_type(Some(user_type))
                .build()
                .unwrap();
            assert_eq!(
                user_list_filter(&cfg(), "default", &params),
                ListDecision::EmptyResult,
                "user_type {user_type:?} should short-circuit"
            );
        }
    }

    #[test]
    fn test_user_list_filter_all_and_nonlocal_still_query() {
        for user_type in [UserType::All, UserType::NonLocal] {
            let params = UserListParametersBuilder::default()
                .user_type(Some(user_type))
                .build()
                .unwrap();
            assert!(matches!(
                user_list_filter(&cfg(), "default", &params),
                ListDecision::Query(_)
            ));
        }
    }

    #[test]
    fn test_group_list_filter_defaults_to_objectclass_only() {
        let params = GroupListParametersBuilder::default().build().unwrap();
        match group_list_filter(&cfg(), "default", &params) {
            ListDecision::Query(f) => assert_eq!(f, "(&(objectClass=groupOfNames)(cn=*))"),
            ListDecision::EmptyResult => panic!("expected a query"),
        }
    }

    #[test]
    fn test_group_list_filter_by_name() {
        let params = GroupListParametersBuilder::default()
            .name("admins")
            .build()
            .unwrap();
        match group_list_filter(&cfg(), "default", &params) {
            ListDecision::Query(f) => {
                assert_eq!(f, "(&(objectClass=groupOfNames)(cn=*)(ou=admins))")
            }
            ListDecision::EmptyResult => panic!("expected a query"),
        }
    }

    #[test]
    fn test_group_list_filter_domain_mismatch_short_circuits() {
        let params = GroupListParametersBuilder::default()
            .domain_id("other-domain")
            .build()
            .unwrap();
        assert_eq!(
            group_list_filter(&cfg(), "default", &params),
            ListDecision::EmptyResult
        );
    }
}
