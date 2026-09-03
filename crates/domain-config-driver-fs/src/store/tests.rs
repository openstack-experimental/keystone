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

use std::fs;
use std::path::Path;

use serde_json::json;
use tempfile::tempdir;
use tracing_test::traced_test;

use openstack_keystone_core_types::domain_config::DomainConfigGroupName;

use super::*;

/// Write `contents` to `dir/name`.
fn write(dir: &Path, name: &str, contents: &str) {
    fs::write(dir.join(name), contents).expect("writing a fixture file");
}

#[test]
fn filename_parsing_strips_only_the_literal_prefix_and_suffix() {
    assert_eq!(
        domain_name_from_filename("keystone.Acme.conf").as_deref(),
        Some("Acme")
    );
    assert_eq!(
        domain_name_from_filename("keystone.my.domain.conf").as_deref(),
        Some("my.domain")
    );
    assert_eq!(domain_name_from_filename("keystone.conf"), None);
    assert_eq!(domain_name_from_filename("acme.conf"), None);
    assert_eq!(domain_name_from_filename("README"), None);
    assert_eq!(domain_name_from_filename("keystone.Acme.conf.bak"), None);
}

#[test]
fn loads_both_groups_keeping_values_verbatim() {
    let dir = tempdir().unwrap();
    write(
        dir.path(),
        "keystone.Acme.conf",
        "[identity]\ndriver = ldap\n\n[ldap]\nurl = ldap://host\npage_size = 10\n",
    );

    let store = DomainConfigStore::load(dir.path()).unwrap();
    let config = store.get("Acme").expect("Acme is configured");

    let identity = config.group(DomainConfigGroupName::Identity).unwrap();
    assert_eq!(identity.get("driver"), Some(&json!("ldap")));

    let ldap = config.group(DomainConfigGroupName::Ldap).unwrap();
    assert_eq!(ldap.get("url"), Some(&json!("ldap://host")));
    // Stored as the string the file spelled it with; coercion happens later.
    assert_eq!(ldap.get("page_size"), Some(&json!("10")));
}

#[traced_test]
#[test]
fn ignores_an_unknown_section_with_a_warning() {
    let dir = tempdir().unwrap();
    write(
        dir.path(),
        "keystone.Acme.conf",
        "[identity]\ndriver = ldap\n\n[assignment]\ndriver = sql\n\n[ldap]\nurl = ldap://host\n",
    );

    let store = DomainConfigStore::load(dir.path()).unwrap();
    let config = store.get("Acme").unwrap();

    assert!(config.group(DomainConfigGroupName::Identity).is_some());
    assert!(config.group(DomainConfigGroupName::Ldap).is_some());
    assert!(logs_contain("unsupported [section]"));
}

#[traced_test]
#[test]
fn drops_an_unknown_option_with_a_warning() {
    let dir = tempdir().unwrap();
    write(
        dir.path(),
        "keystone.Acme.conf",
        "[ldap]\nbogus_opt = x\nurl = ldap://host\n",
    );

    let store = DomainConfigStore::load(dir.path()).unwrap();
    let ldap = store
        .get("Acme")
        .unwrap()
        .group(DomainConfigGroupName::Ldap)
        .unwrap();

    assert_eq!(ldap.get("url"), Some(&json!("ldap://host")));
    assert_eq!(ldap.get("bogus_opt"), None);
    assert!(logs_contain("bogus_opt"));
}

#[test]
fn keeps_a_sensitive_option_in_the_whole_config_but_not_on_the_wire() {
    let dir = tempdir().unwrap();
    write(
        dir.path(),
        "keystone.Acme.conf",
        "[ldap]\nurl = ldap://host\npassword = s3cr3t\n",
    );

    let store = DomainConfigStore::load(dir.path()).unwrap();
    let config = store.get("Acme").unwrap();

    let ldap = config.group(DomainConfigGroupName::Ldap).unwrap();
    assert_eq!(ldap.get("password"), Some(&json!("s3cr3t")));

    let serialized = serde_json::to_value(config).unwrap();
    assert!(
        serialized.pointer("/ldap/password").is_none(),
        "the bind password must not serialize: {serialized}"
    );
}

#[test]
fn a_group_of_only_a_sensitive_option_is_still_configured() {
    let dir = tempdir().unwrap();
    write(
        dir.path(),
        "keystone.Acme.conf",
        "[ldap]\npassword = s3cr3t\n",
    );

    let store = DomainConfigStore::load(dir.path()).unwrap();
    let config = store
        .get("Acme")
        .expect("a sensitive-only group still counts as configured");
    assert!(!config.is_empty());
}

#[test]
fn an_unknown_domain_has_no_configuration() {
    let dir = tempdir().unwrap();
    let store = DomainConfigStore::load(dir.path()).unwrap();
    assert!(store.get("nope").is_none());
}

#[traced_test]
#[test]
fn a_missing_directory_is_an_empty_store_not_an_error() {
    let store = DomainConfigStore::load(Path::new("/no/such/keystone/domains")).unwrap();
    assert!(store.get("anything").is_none());
    assert!(logs_contain("does not exist"));
}

#[test]
fn a_malformed_file_fails_the_load_naming_the_file() {
    let dir = tempdir().unwrap();
    write(
        dir.path(),
        "keystone.Acme.conf",
        "[identity\ndriver = ldap\n",
    );

    let err = DomainConfigStore::load(dir.path()).expect_err("a malformed file fails startup");
    let message = err.to_string();
    assert!(message.contains("keystone.Acme.conf"), "{message}");
}

#[traced_test]
#[test]
fn files_that_configure_nothing_are_skipped_with_a_warning() {
    let dir = tempdir().unwrap();
    write(dir.path(), "keystone.Empty.conf", "");
    write(
        dir.path(),
        "keystone.Unknown.conf",
        "[assignment]\ndriver = sql\n",
    );
    write(dir.path(), "keystone.Blank.conf", "[ldap]\n");

    let store = DomainConfigStore::load(dir.path()).unwrap();

    for domain in ["Empty", "Unknown", "Blank"] {
        assert!(store.get(domain).is_none(), "{domain} configures nothing");
    }
    assert!(logs_contain("no usable configuration"));
}

#[traced_test]
#[test]
fn only_keystone_dot_name_dot_conf_files_are_read() {
    let dir = tempdir().unwrap();
    write(
        dir.path(),
        "keystone.Acme.conf",
        "[identity]\ndriver = ldap\n",
    );
    write(dir.path(), "README", "not a config\n");
    write(dir.path(), "keystone.conf", "[identity]\ndriver = sql\n");
    write(dir.path(), "acme.conf", "[identity]\ndriver = sql\n");
    fs::create_dir(dir.path().join("keystone.Sub.conf")).unwrap();

    let store = DomainConfigStore::load(dir.path()).unwrap();

    assert!(store.get("Acme").is_some());
    assert!(store.get("").is_none());
    assert!(logs_contain("not named keystone.<domain_name>.conf"));
}

#[test]
fn a_domain_name_may_contain_dots() {
    let dir = tempdir().unwrap();
    write(
        dir.path(),
        "keystone.my.domain.conf",
        "[identity]\ndriver = ldap\n",
    );

    let store = DomainConfigStore::load(dir.path()).unwrap();
    assert!(store.get("my.domain").is_some());
}

#[traced_test]
#[test]
fn section_names_are_matched_case_sensitively() {
    let dir = tempdir().unwrap();
    write(
        dir.path(),
        "keystone.Acme.conf",
        "[Identity]\ndriver = ldap\n",
    );

    let store = DomainConfigStore::load(dir.path()).unwrap();

    assert!(store.get("Acme").is_none(), "[Identity] is not [identity]");
    assert!(logs_contain("unsupported [section]"));
}
