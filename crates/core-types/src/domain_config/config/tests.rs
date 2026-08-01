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

//! # Domain configuration structure tests

use std::collections::HashSet;

use secrecy::{ExposeSecret, SecretString};
use serde_json::json;

use super::*;
use crate::domain_config::{
    LDAP_WHITELISTED_OPTIONS, is_sensitive, sensitive_options, whitelisted_options,
};

const PASSWORD: &str = "ldap-top-secret";

/// A configuration exercising both groups, a sensitive option and every
/// scalar kind the `ldap` group can hold.
fn sample_config() -> DomainConfig {
    config_from(json!({
        "identity": {"driver": "ldap", "list_limit": 100},
        "ldap": {
            "url": "ldap://myldap.com:389/",
            "user_tree_dn": "ou=Users,dc=example,dc=com",
            "password": PASSWORD,
            "page_size": 10,
            "use_tls": true,
            "pool_retry_delay": 0.5,
            "user_attribute_ignore": ["default_project_id"],
        },
    }))
}

/// Build a configuration from a request body, failing the test if it is
/// rejected.
fn config_from(value: Value) -> DomainConfig {
    DomainConfig::from_value(value).expect("a valid domain configuration")
}

/// Option names of a group, as flattened for storage.
fn option_names(options: &[DomainConfigOption], group: DomainConfigGroupName) -> HashSet<String> {
    options
        .iter()
        .filter(|option| option.group == group)
        .map(|option| option.option.clone())
        .collect()
}

#[test]
fn config_round_trips_through_options() {
    let options = sample_config().to_options();
    assert_eq!(
        option_names(&options, DomainConfigGroupName::Identity),
        HashSet::from(["driver".to_string(), "list_limit".to_string()])
    );

    let restored = DomainConfig::from_options(options);
    let ldap = restored.group(DomainConfigGroupName::Ldap).expect("ldap");
    assert_eq!(ldap.get("url"), Some(&json!("ldap://myldap.com:389/")));
    assert_eq!(ldap.get("page_size"), Some(&json!(10)));
    assert_eq!(ldap.get("use_tls"), Some(&json!(true)));
    assert_eq!(ldap.get("pool_retry_delay"), Some(&json!(0.5)));
    assert_eq!(
        ldap.get("user_attribute_ignore"),
        Some(&json!(["default_project_id"]))
    );
    assert_eq!(ldap.get("password"), Some(&json!(PASSWORD)));
    assert_eq!(
        restored
            .group(DomainConfigGroupName::Identity)
            .and_then(|group| group.get("list_limit")),
        Some(&json!(100))
    );
}

#[test]
fn values_are_stored_verbatim() {
    // Whatever JSON type a client wrote is what a read gives back: the
    // persistence layer keeps `JsonBlob` columns, as python-keystone does.
    let config = config_from(json!({"ldap": {"page_size": "10", "use_tls": "True"}}));
    let ldap = config.group(DomainConfigGroupName::Ldap).expect("ldap");
    assert_eq!(ldap.get("page_size"), Some(&json!("10")));
    assert_eq!(ldap.get("use_tls"), Some(&json!("True")));
}

#[test]
fn to_options_flags_the_password_as_sensitive() {
    let options = sample_config().to_options();
    let password = options
        .iter()
        .find(|option| option.option == "password")
        .expect("the password is stored");
    assert!(password.sensitive());
    assert_eq!(password.group, DomainConfigGroupName::Ldap);
    assert!(
        options
            .iter()
            .filter(|option| option.option != "password")
            .all(|option| !option.sensitive())
    );
}

#[test]
fn config_does_not_serialize_the_password() {
    let rendered = serde_json::to_string(&sample_config()).expect("serializable");
    assert!(
        !rendered.contains(PASSWORD),
        "the password reached the wire"
    );
    assert!(!rendered.contains("password"));
    assert!(rendered.contains("ldap://myldap.com:389/"));
}

#[test]
fn a_group_holding_only_a_secret_is_not_serialized() {
    let config = config_from(json!({"ldap": {"password": PASSWORD}}));
    assert_eq!(
        serde_json::to_value(&config).expect("serializable"),
        json!({})
    );
    assert_eq!(
        serde_json::to_value(config.group(DomainConfigGroupName::Ldap)).expect("serializable"),
        json!({})
    );
}

#[test]
fn config_debug_does_not_leak_the_password() {
    let rendered = format!("{:?}", sample_config());
    assert!(!rendered.contains(PASSWORD), "the password reached a log");
    assert!(rendered.contains("REDACTED"));
    assert!(rendered.contains("ldap://myldap.com:389/"));
}

#[test]
fn config_deserializes_the_password() {
    // Sensitive options are write-only, not unwritable.
    let config: DomainConfig =
        serde_json::from_value(json!({"ldap": {"password": PASSWORD}})).expect("deserializable");
    assert_eq!(
        config
            .group(DomainConfigGroupName::Ldap)
            .and_then(|group| group.get("password")),
        Some(&json!(PASSWORD))
    );
}

#[test]
fn config_drops_options_outside_the_whitelist() {
    // python-keystone's `_config_to_list` ignores an option it does not
    // recognize rather than failing the request.
    let config = config_from(json!({"ldap": {"url": "ldap://host", "bind_dn": "cn=admin"}}));
    let ldap = config.group(DomainConfigGroupName::Ldap).expect("ldap");
    assert_eq!(ldap.get("url"), Some(&json!("ldap://host")));
    assert_eq!(ldap.get("bind_dn"), None);

    // An option of the *other* group is not whitelisted here either.
    let config = config_from(json!({"ldap": {"url": "ldap://host", "driver": "sql"}}));
    assert_eq!(
        config
            .group(DomainConfigGroupName::Ldap)
            .and_then(|group| group.get("driver")),
        None
    );
}

#[test]
fn set_rejects_an_option_outside_the_whitelist() {
    let mut config = DomainConfig::new();
    let err = config
        .set(DomainConfigGroupName::Ldap, "bind_dn", "cn=admin")
        .expect_err("an unsupported option is refused");
    assert_eq!(
        err.to_string(),
        "option bind_dn in group ldap is not supported for domain specific configurations"
    );
    config
        .set(DomainConfigGroupName::Ldap, "url", "ldap://host")
        .expect("a whitelisted option is accepted");
    config
        .set(DomainConfigGroupName::Ldap, "password", PASSWORD)
        .expect("a sensitive option is writable");
}

#[test]
fn config_skips_unsupported_options_on_read() {
    // A stored option that is no longer whitelisted must not make the whole
    // configuration unreadable, and with it the domain's identity backend
    // uninitializable.
    let config = DomainConfig::from_options([
        DomainConfigOption::new(DomainConfigGroupName::Ldap, "url", "ldap://host"),
        DomainConfigOption::new(DomainConfigGroupName::Ldap, "removed_option", "value"),
    ]);
    let ldap = config.group(DomainConfigGroupName::Ldap).expect("ldap");
    assert_eq!(ldap.get("url"), Some(&json!("ldap://host")));
    assert_eq!(ldap.get("removed_option"), None);
}

#[test]
fn config_rejects_unknown_groups() {
    let err = DomainConfig::from_value(json!({"assignment": {"driver": "sql"}}))
        .expect_err("an unsupported group is refused");
    assert_eq!(
        err.to_string(),
        "group assignment is not supported for domain specific configurations"
    );
}

#[test]
fn a_group_left_empty_by_the_whitelist_is_storable() {
    // python-keystone checks the shape of the payload before it looks at the
    // option names, warns about the ones it does not recognize and stores what
    // is left — nothing, here — rather than failing the request.
    let config = config_from(json!({"ldap": {"bind_dn": "cn=admin"}}));
    config
        .validate()
        .expect("a group the whitelist emptied is not an empty request");
    assert!(config.is_empty());
    assert!(config.to_options().is_empty());
}

#[test]
fn config_rejects_an_empty_payload() {
    for value in [json!({}), json!(null), json!("ldap")] {
        let err = DomainConfig::from_value(value.clone()).expect_err("refused");
        assert_eq!(err.to_string(), "no options specified", "{value}");
    }
    let err = DomainConfig::new()
        .validate()
        .expect_err("an empty configuration is refused");
    assert_eq!(err.to_string(), "no options specified");
}

#[test]
fn config_rejects_a_group_that_is_not_a_mapping_of_options() {
    for value in [json!({"ldap": {}}), json!({"ldap": "ldap://host"})] {
        let err = DomainConfig::from_value(value.clone()).expect_err("refused");
        assert_eq!(
            err.to_string(),
            "the value of group ldap specified in the config should be a dictionary of options",
            "{value}"
        );
    }
}

#[test]
fn validate_accepts_a_group_holding_only_the_password() {
    // A domain may configure nothing but its bind password; the group is not
    // empty just because nothing in it is readable.
    config_from(json!({"ldap": {"password": PASSWORD}}))
        .validate()
        .expect("a sensitive option is an option");
}

#[test]
fn group_round_trips_through_options() {
    let group = DomainConfigGroup::from_options(
        DomainConfigGroupName::Identity,
        [DomainConfigOption::new(
            DomainConfigGroupName::Identity,
            "driver",
            "ldap",
        )],
    )
    .expect("a group of its own options");
    assert_eq!(group.name(), DomainConfigGroupName::Identity);
    assert_eq!(group.get("driver"), Some(&json!("ldap")));
    assert_eq!(group.to_options().len(), 1);

    let config = group.into_config();
    assert!(config.group(DomainConfigGroupName::Ldap).is_none());
    assert!(!config.is_empty());
}

#[test]
fn group_rejects_options_of_another_group() {
    let err = DomainConfigGroup::from_options(
        DomainConfigGroupName::Identity,
        [DomainConfigOption::new(
            DomainConfigGroupName::Ldap,
            "url",
            "ldap://host",
        )],
    )
    .expect_err("an option of another group is refused");
    assert_eq!(
        err.to_string(),
        "option url in group identity is not supported for domain specific configurations"
    );
}

mod values {
    //! What an option may hold is defined by the config section it overrides,
    //! not by this module; these check that it is really consulted.

    use super::*;

    #[test]
    fn accepts_the_config_file_spelling_of_a_value() {
        // Every value of a per-domain `keystone.<domain>.conf` is a string.
        config_from(json!({"ldap": {
            "use_tls": "True",
            "page_size": "10",
            "pool_retry_delay": "0.1",
            "user_attribute_ignore": "mail,enabled",
            "tls_req_cert": "never",
        }}))
        .validate_values()
        .expect("oslo.config spellings are accepted");
    }

    #[test]
    fn accepts_integer_spelled_booleans() {
        config_from(json!({"ldap": {"use_tls": 1, "use_pool": 0}}))
            .validate_values()
            .expect("0/1 are accepted for a boolean");
    }

    #[test]
    fn rejects_a_value_the_option_cannot_hold() {
        let err = config_from(json!({"ldap": {"page_size": "ten"}}))
            .validate_values()
            .expect_err("a page size is an integer");
        assert_eq!(
            err.to_string(),
            "invalid value for option page_size in group ldap: expected an integer, got `\"ten\"`"
        );
    }

    #[test]
    fn names_the_offending_option_among_many() {
        // serde reports a failing value without naming the field it came from,
        // which on a 49 option group leaves an operator guessing.
        let err = config_from(json!({"ldap": {
            "url": "ldap://host",
            "page_size": 10,
            "use_tls": "maybe",
            "suffix": "dc=example,dc=com",
        }}))
        .validate_values()
        .expect_err("a boolean is a boolean");
        assert_eq!(
            err.to_string(),
            "invalid value for option use_tls in group ldap: expected a boolean, got `\"maybe\"`"
        );
    }

    #[test]
    fn accepts_both_spellings_of_the_identity_list_limit() {
        for value in [json!(100), json!("100")] {
            config_from(json!({"identity": {"list_limit": value}}))
                .validate_values()
                .expect("a page size");
        }
        let err = config_from(json!({"identity": {"list_limit": "many"}}))
            .validate_values()
            .expect_err("refused");
        assert!(
            err.to_string()
                .starts_with("invalid value for option list_limit in group identity"),
            "{err}"
        );
    }
}

mod resolution {
    //! The point of the whole module: a domain's options resolve into the very
    //! struct the identity backend is configured with.

    use super::*;

    #[test]
    fn overlays_the_domain_options_onto_the_global_section() {
        let mut config = Config::default();
        config.ldap.url = "ldap://global".to_string();
        config.ldap.suffix = "dc=global".to_string();

        let ldap = config_from(json!({"ldap": {"url": "ldap://domain", "page_size": "25"}}))
            .resolve_ldap(&config)
            .expect("resolvable");
        assert_eq!(ldap.url, "ldap://domain");
        assert_eq!(ldap.page_size, 25);
        // Untouched options keep the global value...
        assert_eq!(ldap.suffix, "dc=global");
        // ...and options the domain may not set keep theirs, defaults
        // included.
        assert_eq!(ldap.user_objectclass, config.ldap.user_objectclass);
    }

    #[test]
    fn keeps_the_global_bind_password_when_the_domain_sets_none() {
        let mut config = Config::default();
        config.ldap.password = Some(SecretString::from("global-secret"));

        let ldap = config_from(json!({"ldap": {"url": "ldap://domain"}}))
            .resolve_ldap(&config)
            .expect("resolvable");
        assert_eq!(
            ldap.password
                .map(|password| password.expose_secret().to_string()),
            Some("global-secret".to_string()),
            "the global bind password must survive the overlay"
        );
    }

    #[test]
    fn takes_the_domain_bind_password_over_the_global_one() {
        let mut config = Config::default();
        config.ldap.password = Some(SecretString::from("global-secret"));

        let ldap = config_from(json!({"ldap": {"password": PASSWORD}}))
            .resolve_ldap(&config)
            .expect("resolvable");
        assert_eq!(
            ldap.password
                .map(|password| password.expose_secret().to_string()),
            Some(PASSWORD.to_string())
        );
    }

    #[test]
    fn an_explicit_null_password_does_not_inherit_the_global_one() {
        let mut config = Config::default();
        config.ldap.password = Some(SecretString::from("global-secret"));

        let ldap = config_from(json!({"ldap": {"password": null}}))
            .resolve_ldap(&config)
            .expect("resolvable");
        assert!(
            ldap.password.is_none(),
            "an explicit null requests an anonymous bind"
        );
    }

    #[test]
    fn keeps_the_global_list_limit_cap_when_the_domain_sets_a_page_size() {
        // `max_list_limit` has no domain-settable spelling of its own, and
        // `list_limit` is whitelisted as the scalar python-keystone spells it,
        // so overriding the page size must not lift the operator's cap on what
        // a client may ask for.
        let mut config = Config::default();
        config.identity.list_limit.list_limit = Some(50);
        config.identity.list_limit.max_list_limit = Some(1000);

        let identity = config_from(json!({"identity": {"list_limit": 100}}))
            .resolve_identity(&config)
            .expect("resolvable");
        assert_eq!(identity.list_limit.list_limit, Some(100));
        assert_eq!(identity.list_limit.max_list_limit, Some(1000));
    }

    #[test]
    fn resolves_a_domain_that_configured_nothing() {
        let mut config = Config::default();
        config.ldap.url = "ldap://global".to_string();
        config.identity.driver = "ldap".to_string();

        let empty = DomainConfig::new();
        assert_eq!(
            empty.resolve_ldap(&config).expect("resolvable").url,
            "ldap://global"
        );
        assert_eq!(
            empty.resolve_identity(&config).expect("resolvable").driver,
            "ldap"
        );
    }

    #[test]
    fn resolves_the_identity_group() {
        let config = Config::default();
        let identity = config_from(json!({"identity": {"driver": "ldap", "list_limit": 100}}))
            .resolve_identity(&config)
            .expect("resolvable");
        assert_eq!(identity.driver, "ldap");
        assert_eq!(identity.list_limit.list_limit, Some(100));
        assert_eq!(
            identity.max_password_length, config.identity.max_password_length,
            "an option a domain cannot set keeps the global value"
        );
    }

    #[test]
    fn reports_the_option_that_cannot_be_resolved() {
        let err = config_from(json!({"ldap": {"page_size": "ten"}}))
            .resolve_ldap(&Config::default())
            .expect_err("a page size is an integer");
        assert_eq!(
            err.to_string(),
            "invalid value for option page_size in group ldap: expected an integer, got `\"ten\"`"
        );
    }

    #[test]
    fn a_substituted_configuration_cannot_reach_a_response() {
        // Expansion inlines the bind password into `ldap.url`, which is a
        // readable option; the type it comes back in is what keeps it off the
        // wire and out of a log.
        let substituted = config_from(json!({"ldap": {
            "url": "ldap://%(password)s@myldap.com:389/",
            "password": PASSWORD,
        }}))
        .substitute();
        assert!(
            substituted
                .option(DomainConfigGroupName::Ldap, "url")
                .and_then(Value::as_str)
                .is_some_and(|url| url.contains(PASSWORD)),
            "the reference resolved, so this is the value that must not escape"
        );
        assert!(!format!("{substituted:?}").contains(PASSWORD));

        let ldap = substituted
            .resolve_ldap(&Config::default())
            .expect("resolvable");
        assert!(
            ldap.url.contains(PASSWORD),
            "the provider received the secret"
        );
        assert_eq!(format!("{ldap:?}"), "ResolvedLdapProvider(REDACTED)");
        assert!(!format!("{ldap:?}").contains(PASSWORD));
    }

    #[test]
    fn resolves_a_substituted_configuration() {
        let config = Config::default();
        let stored = config_from(json!({"ldap": {
            "url": "ldap://%(user)s:%(password)s@myldap.com:389/",
            "user": "cn=admin",
            "password": PASSWORD,
        }}));
        let ldap = stored
            .substitute()
            .resolve_ldap(&config)
            .expect("resolvable");
        assert_eq!(
            ldap.url.as_str(),
            format!("ldap://cn=admin:{PASSWORD}@myldap.com:389/")
        );
    }
}

#[test]
fn every_configurable_option_is_an_option_of_the_config_section() {
    // The anti-drift check: the whitelist names options of the very sections
    // it overrides, so an option that is renamed or dropped there fails here
    // rather than silently becoming unsettable.
    let sections = [
        (
            DomainConfigGroupName::Identity,
            serde_json::to_value(IdentityProvider::default()).expect("serializable"),
        ),
        (
            DomainConfigGroupName::Ldap,
            serde_json::to_value(LdapProvider::default()).expect("serializable"),
        ),
    ];
    for (group, section) in sections {
        let section = section.as_object().expect("a config section is a mapping");
        for option in whitelisted_options(group) {
            assert!(
                section.contains_key(*option),
                "`{option}` is whitelisted for group {group} but is not an option of its config section"
            );
        }
    }

    // Sensitive options are never serialized, so they are checked by writing
    // one: `ldap.password` has to reach `LdapProvider::password`.
    assert_eq!(
        sensitive_options(DomainConfigGroupName::Ldap),
        &["password"]
    );
    let ldap = config_from(json!({"ldap": {"password": PASSWORD}}))
        .resolve_ldap(&Config::default())
        .expect("resolvable");
    assert_eq!(
        ldap.password
            .map(|password| password.expose_secret().to_string()),
        Some(PASSWORD.to_string())
    );
}

#[test]
fn defaults_cover_every_whitelisted_option() {
    let config = Config::default();
    let options = DomainConfig::default_options(&config, None).expect("defaults");

    for group in DomainConfigGroupName::ALL {
        let expected: HashSet<String> = whitelisted_options(*group)
            .iter()
            .map(|option| (*option).to_string())
            .collect();
        assert_eq!(
            option_names(&options, *group),
            expected,
            "default options of group {group} drifted from the whitelist"
        );
    }
}

#[test]
fn defaults_never_include_sensitive_options() {
    let mut config = Config::default();
    config.ldap.password = Some(SecretString::from(PASSWORD));

    let options = DomainConfig::default_options(&config, None).expect("defaults");
    for option in &options {
        assert!(
            !is_sensitive(option.group, &option.option),
            "{} leaked into the defaults",
            option.option
        );
    }
    let defaults = DomainConfig::defaults(&config).expect("defaults");
    assert!(
        defaults
            .group(DomainConfigGroupName::Ldap)
            .and_then(|group| group.get("password"))
            .is_none()
    );
    assert!(!format!("{defaults:?}").contains(PASSWORD));
}

#[test]
fn defaults_carry_the_configured_values() {
    let mut config = Config::default();
    config.identity.driver = "ldap".to_string();
    config.ldap.url = "ldaps://ldap.example.com".to_string();
    config.ldap.page_size = 42;
    config.ldap.use_tls = true;
    config.ldap.pool = false;

    let defaults = DomainConfig::defaults(&config).expect("defaults");
    assert_eq!(
        defaults
            .group(DomainConfigGroupName::Identity)
            .and_then(|group| group.get("driver")),
        Some(&json!("ldap"))
    );
    let ldap = defaults.group(DomainConfigGroupName::Ldap).expect("ldap");
    assert_eq!(ldap.get("url"), Some(&json!("ldaps://ldap.example.com")));
    assert_eq!(ldap.get("page_size"), Some(&json!(42)));
    assert_eq!(ldap.get("use_tls"), Some(&json!(true)));
    // python-keystone's spelling of the pooling flags is the one the API
    // contract uses, and now the one the config section carries.
    assert_eq!(ldap.get("use_pool"), Some(&json!(false)));
    assert_eq!(ldap.get("use_auth_pool"), Some(&json!(true)));
}

#[test]
fn defaults_report_a_list_option_as_a_list() {
    let defaults = DomainConfig::defaults(&Config::default()).expect("defaults");
    let ldap = defaults.group(DomainConfigGroupName::Ldap).expect("ldap");
    assert_eq!(
        ldap.get("user_attribute_ignore"),
        Some(&json!(["default_project_id"])),
        "oslo.config's list options are reported as lists"
    );
    assert_eq!(
        ldap.get("user_additional_attribute_mapping"),
        Some(&json!([]))
    );
}

#[test]
fn identity_list_limit_default_falls_back_to_the_global_one() {
    // `Config::resolve_list_limit` resolves `[identity] list_limit` through
    // `[DEFAULT] list_limit`. The defaults endpoint exists to tell an operator
    // the value a domain inherits, so it has to follow the same chain.
    let mut config = Config::default();
    config.default.list_limit = Some(200);
    assert_eq!(config.identity.list_limit.list_limit, None);
    assert_eq!(
        DomainConfig::default_option(&config, DomainConfigGroupName::Identity, "list_limit")
            .expect("readable")
            .map(DomainConfigValue::into_value),
        Some(json!(200)),
        "the global list_limit is what identity listings are really capped at"
    );

    // The section-local value still wins when it is set.
    config.identity.list_limit.list_limit = Some(50);
    assert_eq!(
        DomainConfig::default_option(&config, DomainConfigGroupName::Identity, "list_limit")
            .expect("readable")
            .map(DomainConfigValue::into_value),
        Some(json!(50))
    );
}

#[test]
fn defaults_of_a_group_are_restricted_to_it() {
    let config = Config::default();
    let options = DomainConfig::default_options(&config, Some(DomainConfigGroupName::Ldap))
        .expect("defaults");
    assert!(
        options
            .iter()
            .all(|option| option.group == DomainConfigGroupName::Ldap)
    );
    assert_eq!(options.len(), LDAP_WHITELISTED_OPTIONS.len());

    let group = DomainConfig::default_group(&config, DomainConfigGroupName::Identity)
        .expect("the identity defaults");
    assert_eq!(group.name(), DomainConfigGroupName::Identity);
    assert_eq!(group.get("driver"), Some(&json!(config.identity.driver)));
}

#[test]
fn default_option_reads_a_single_value() {
    let config = Config::default();
    let value = DomainConfig::default_option(&config, DomainConfigGroupName::Identity, "driver")
        .expect("readable")
        .expect("driver default");
    assert_eq!(value.as_str(), Some(config.identity.driver.as_str()));
}

#[test]
fn default_option_keeps_unconfigured_options_as_null() {
    // `[ldap] user` has no default, and python-keystone still reports it.
    let value =
        DomainConfig::default_option(&Config::default(), DomainConfigGroupName::Ldap, "user")
            .expect("readable")
            .expect("user default");
    assert!(value.as_value().is_null());
}

#[test]
fn default_option_refuses_sensitive_options() {
    for option in sensitive_options(DomainConfigGroupName::Ldap) {
        let err =
            DomainConfig::default_option(&Config::default(), DomainConfigGroupName::Ldap, option)
                .expect_err("a secret has no readable default");
        assert_eq!(
            err.to_string(),
            format!(
                "option {option} in group ldap is not supported for domain specific configurations"
            )
        );
    }
}

#[test]
fn create_and_update_wrap_a_config() {
    let create = DomainConfigCreate::from(sample_config());
    assert_eq!(
        create
            .group(DomainConfigGroupName::Ldap)
            .and_then(|group| group.get("url")),
        Some(&json!("ldap://myldap.com:389/"))
    );
    assert!(!create.into_inner().is_empty());

    let mut update = DomainConfigUpdate::default();
    assert!(update.is_empty());
    update
        .set(DomainConfigGroupName::Identity, "driver", "sql")
        .expect("a whitelisted option");
    assert!(!update.is_empty());
    assert_eq!(DomainConfig::from(update).to_options().len(), 1);
}

mod substitution {
    use super::*;

    /// An `ldap` group whose `url` references other options of the group.
    fn config_with_references(url: &str) -> DomainConfig {
        config_from(json!({"ldap": {
            "url": url,
            "user": "cn=admin",
            "password": PASSWORD,
        }}))
    }

    /// The `ldap.url` of a substituted configuration.
    fn substituted_url(config: &DomainConfig) -> String {
        config
            .substitute()
            .option(DomainConfigGroupName::Ldap, "url")
            .and_then(Value::as_str)
            .expect("the url survives substitution")
            .to_string()
    }

    #[test]
    fn resolves_a_sensitive_reference() {
        assert_eq!(
            substituted_url(&config_with_references(
                "ldap://%(user)s:%(password)s@myldap.com:389/"
            )),
            format!("ldap://cn=admin:{PASSWORD}@myldap.com:389/")
        );
    }

    #[test]
    fn leaves_the_stored_value_untouched() {
        let config = config_with_references("ldap://%(password)s@myldap.com:389/");
        config.substitute();
        assert_eq!(
            config
                .group(DomainConfigGroupName::Ldap)
                .and_then(|group| group.get("url")),
            Some(&json!("ldap://%(password)s@myldap.com:389/")),
            "substitution must not rewrite what is stored and returned by the API"
        );
    }

    #[test]
    fn keeps_a_value_that_references_nothing() {
        assert_eq!(
            substituted_url(&config_with_references("ldap://myldap.com:389/")),
            "ldap://myldap.com:389/"
        );
    }

    #[test]
    fn keeps_a_value_referencing_an_option_that_is_not_configured() {
        // python-keystone warns and leaves the value as it is rather than
        // failing the read of the whole configuration.
        assert_eq!(
            substituted_url(&config_with_references("ldap://%(suffix)s/")),
            "ldap://%(suffix)s/"
        );
    }

    #[test]
    fn keeps_a_malformed_reference() {
        for url in [
            "ldap://%(password@myldap.com/",
            "ldap://%(password)d@myldap.com/",
            "ldap://100%@myldap.com/",
        ] {
            assert_eq!(substituted_url(&config_with_references(url)), url);
        }
    }

    #[test]
    fn unescapes_a_literal_percent() {
        assert_eq!(
            substituted_url(&config_with_references("ldap://myldap.com/100%%")),
            "ldap://myldap.com/100%"
        );
    }

    #[test]
    fn does_not_substitute_into_a_secret() {
        let config = config_from(json!({"ldap": {"user": "cn=admin", "password": "%(user)s"}}));
        assert_eq!(
            config
                .substitute()
                .option(DomainConfigGroupName::Ldap, "password"),
            Some(&json!("%(user)s"))
        );
    }

    #[test]
    fn does_not_cross_group_boundaries() {
        let config = config_from(json!({
            "identity": {"driver": "%(password)s"},
            "ldap": {"password": PASSWORD},
        }));
        assert_eq!(
            config
                .substitute()
                .option(DomainConfigGroupName::Identity, "driver"),
            Some(&json!("%(password)s")),
            "an option must not reach the secrets of another group"
        );
    }

    #[test]
    fn leaves_values_that_are_not_strings_alone() {
        let config = config_from(json!({"ldap": {
            "page_size": 10,
            "use_tls": true,
            "password": PASSWORD,
        }}));
        let substituted = config.substitute();
        assert_eq!(
            substituted.option(DomainConfigGroupName::Ldap, "page_size"),
            Some(&json!(10))
        );
        assert_eq!(
            substituted.option(DomainConfigGroupName::Ldap, "use_tls"),
            Some(&json!(true))
        );
    }

    #[test]
    fn keeps_an_unconfigured_group_unconfigured() {
        assert!(
            config_with_references("ldap://myldap.com/")
                .substitute()
                .option(DomainConfigGroupName::Identity, "driver")
                .is_none()
        );
    }
}
