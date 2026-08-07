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
//! Conversion between stored rows and configuration options.
//!
//! Both tables hold the value as the JSON encoding of whatever the client
//! wrote, in a text column, which is how python-keystone's `JsonBlob` type
//! persists it.

use std::str::FromStr;

use sea_orm::entity::*;

use openstack_keystone_core_types::domain_config::*;

use crate::entity::{sensitive_config, whitelisted_config};

/// Decode a stored row into a configuration option.
///
/// Rows are read tolerantly, the way
/// [`DomainConfig::from_options`] treats options it no longer knows: a row that
/// is no longer configurable is skipped with a warning rather than made to fail
/// the whole read, which would leave the domain unreadable — and its identity
/// backend uninitializable — until an operator deleted the row.
///
/// A row drifts out of the configurable set in two ways, and both are dropped
/// here, at the one place every read passes through. Dropping them at different
/// depths is what would make them behave differently: a group no longer
/// configurable would leave the domain unconfigured (`404`), while an option no
/// longer whitelisted would survive as far as the emptiness check the reads
/// make their `None` decision on and answer an empty configuration (`200`)
/// instead — and would be served outright by the option scoped read, which has
/// no later [`DomainConfig::from_options`] to drop it.
///
/// # Parameters
/// - `group`: The stored group name.
/// - `option`: The stored option name.
/// - `value`: The stored, JSON encoded value.
///
/// # Returns
/// - `Result<Option<DomainConfigOption>, DomainConfigProviderError>` - The
///   option, `None` when it is not one a domain can hold, or
///   [`DomainConfigProviderError::InvalidOptionValue`] when the value is not
///   the JSON the column is supposed to hold.
fn decode(
    group: &str,
    option: String,
    value: &str,
) -> Result<Option<DomainConfigOption>, DomainConfigProviderError> {
    let Ok(group) = DomainConfigGroupName::from_str(group) else {
        tracing::warn!(
            group = %group,
            option = %option,
            "skipping a stored domain config option of a group that is not configurable"
        );
        return Ok(None);
    };
    // Both tables are read through here, so this has to admit the sensitive
    // options as well as the whitelisted ones.
    if !is_supported(group, &option) {
        tracing::warn!(
            group = %group,
            option = %option,
            "skipping a stored domain config option that is not configurable"
        );
        return Ok(None);
    }
    let value: DomainConfigValue = serde_json::from_str(value).map_err(|source| {
        DomainConfigProviderError::InvalidOptionValue {
            group: group.to_string(),
            option: option.clone(),
            source,
        }
    })?;
    Ok(Some(DomainConfigOption::new(group, option, value)))
}

/// Encode an option value the way both tables store it.
///
/// # Parameters
/// - `option`: The option whose value to encode.
///
/// # Returns
/// - `Result<String, DomainConfigProviderError>` - The JSON encoding of the
///   value.
fn encode(option: &DomainConfigOption) -> Result<String, DomainConfigProviderError> {
    serde_json::to_string(&option.value).map_err(|source| {
        DomainConfigProviderError::InvalidOptionValue {
            group: option.group.to_string(),
            option: option.option.clone(),
            source,
        }
    })
}

/// Decode the readable rows of a query.
///
/// # Parameters
/// - `rows`: The rows to decode.
///
/// # Returns
/// - `Result<Vec<DomainConfigOption>, DomainConfigProviderError>` - The
///   options, skipping the rows [`decode`] does not recognize.
pub(crate) fn from_whitelisted_rows<I>(
    rows: I,
) -> Result<Vec<DomainConfigOption>, DomainConfigProviderError>
where
    I: IntoIterator<Item = whitelisted_config::Model>,
{
    rows.into_iter()
        .filter_map(|row| decode(&row.group, row.option, &row.value).transpose())
        .collect()
}

/// Decode the sensitive rows of a query.
///
/// # Parameters
/// - `rows`: The rows to decode.
///
/// # Returns
/// - `Result<Vec<DomainConfigOption>, DomainConfigProviderError>` - The
///   options, skipping the rows [`decode`] does not recognize.
pub(crate) fn from_sensitive_rows<I>(
    rows: I,
) -> Result<Vec<DomainConfigOption>, DomainConfigProviderError>
where
    I: IntoIterator<Item = sensitive_config::Model>,
{
    rows.into_iter()
        .filter_map(|row| decode(&row.group, row.option, &row.value).transpose())
        .collect()
}

/// Build the rows an option list is persisted as.
///
/// Sensitivity is a property of the option name, so the split decides the
/// table an option lands in: a secret only ever reaches `sensitive_config`,
/// which the readable endpoints do not query.
///
/// # Parameters
/// - `domain_id`: The domain the options belong to.
/// - `options`: The options to persist.
///
/// # Returns
/// - `Result<(Vec<whitelisted_config::ActiveModel>, Vec<sensitive_config::ActiveModel>), DomainConfigProviderError>` -
///   The readable and the sensitive rows.
#[allow(clippy::type_complexity)]
pub(crate) fn to_rows<'a, I>(
    domain_id: &str,
    options: I,
) -> Result<
    (
        Vec<whitelisted_config::ActiveModel>,
        Vec<sensitive_config::ActiveModel>,
    ),
    DomainConfigProviderError,
>
where
    I: IntoIterator<Item = &'a DomainConfigOption>,
{
    let mut whitelisted = Vec::new();
    let mut sensitive = Vec::new();
    for option in options {
        let value = encode(option)?;
        if option.sensitive() {
            sensitive.push(sensitive_config::ActiveModel {
                domain_id: Set(domain_id.to_string()),
                group: Set(option.group.to_string()),
                option: Set(option.option.clone()),
                value: Set(value),
            });
        } else {
            whitelisted.push(whitelisted_config::ActiveModel {
                domain_id: Set(domain_id.to_string()),
                group: Set(option.group.to_string()),
                option: Set(option.option.clone()),
                value: Set(value),
            });
        }
    }
    Ok((whitelisted, sensitive))
}

/// Reject an option that may not be stored for a domain.
///
/// The option scoped write addresses one option rather than a group, so it is
/// the one path that has to ask for both checks by hand: an option that is not
/// supported, or one holding a value its type cannot represent, would be
/// stored only for every later read of the domain to trip over it. An
/// unsupported name is merely skipped with a warning, but an untypable value
/// fails the domain's identity backend outright, which is what leaves it
/// uninitializable until an operator deletes the row.
///
/// # Parameters
/// - `option`: The option to check.
///
/// # Returns
/// - `Result<(), DomainConfigProviderError>` - `Ok(())` when the option may be
///   stored, [`DomainConfigProviderError::UnsupportedOption`] when its name is
///   not configurable, or [`DomainConfigProviderError::InvalidOptionValue`]
///   when the value is not one the option can hold.
pub(crate) fn assert_storable(
    option: &DomainConfigOption,
) -> Result<(), DomainConfigProviderError> {
    if !is_supported(option.group, &option.option) {
        return Err(DomainConfigProviderError::UnsupportedOption {
            group: option.group.to_string(),
            option: option.option.clone(),
        });
    }
    // The config section the option overrides is the only thing that knows
    // what it may hold.
    DomainConfigGroup::from_options(option.group, [option.clone()])?.validate_values()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_stored_row() {
        let option = decode("ldap", "url".to_string(), r#""ldap://host""#)
            .unwrap()
            .unwrap();
        assert_eq!(option.group, DomainConfigGroupName::Ldap);
        assert_eq!(option.option, "url");
        assert_eq!(option.value.as_str(), Some("ldap://host"));
        assert!(!option.sensitive());
    }

    #[test]
    fn decodes_the_json_type_that_was_stored() {
        let option = decode("ldap", "page_size".to_string(), "10")
            .unwrap()
            .unwrap();
        assert_eq!(option.value, DomainConfigValue::new(10));
    }

    #[test]
    fn decoding_marks_a_sensitive_option() {
        let option = decode("ldap", "password".to_string(), r#""s3cr3t""#)
            .unwrap()
            .unwrap();
        assert!(option.sensitive());
    }

    #[test]
    fn decoding_skips_a_group_that_is_not_configurable() {
        assert!(
            decode("assignment", "driver".to_string(), r#""sql""#)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn decoding_skips_an_option_that_is_not_configurable() {
        assert!(
            decode("ldap", "bind_dn".to_string(), r#""cn=admin""#)
                .unwrap()
                .is_none()
        );
    }

    /// The sensitive options are configurable too, and both tables decode
    /// through here, so the whitelist alone must not be the test.
    #[test]
    fn decoding_keeps_a_sensitive_option() {
        let option = decode("ldap", "password".to_string(), r#""s3cr3t""#)
            .unwrap()
            .expect("a sensitive option is still configurable");
        assert!(option.sensitive());
    }

    #[test]
    fn decoding_reports_a_value_that_is_not_json() {
        let err = decode("ldap", "url".to_string(), "ldap://host").unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid value for option url in group ldap: expected value at line 1 column 1"
        );
    }

    #[test]
    fn encoding_round_trips_through_decoding() {
        for value in [
            DomainConfigValue::from("ldap://host"),
            DomainConfigValue::new(10),
            DomainConfigValue::new(true),
        ] {
            let option = DomainConfigOption::new(DomainConfigGroupName::Ldap, "url", value.clone());
            let encoded = encode(&option).unwrap();
            assert_eq!(
                decode("ldap", "url".to_string(), &encoded)
                    .unwrap()
                    .unwrap()
                    .value,
                value
            );
        }
    }

    #[test]
    fn sensitive_options_are_split_off_into_their_own_rows() {
        let options = vec![
            DomainConfigOption::new(DomainConfigGroupName::Ldap, "url", "ldap://host"),
            DomainConfigOption::new(DomainConfigGroupName::Ldap, "password", "s3cr3t"),
        ];
        let (whitelisted, sensitive) = to_rows("did", &options).unwrap();
        assert_eq!(whitelisted.len(), 1);
        assert_eq!(sensitive.len(), 1);
        assert_eq!(whitelisted[0].option, Set("url".to_string()));
        assert_eq!(sensitive[0].option, Set("password".to_string()));
        assert_eq!(sensitive[0].value, Set(r#""s3cr3t""#.to_string()));
    }

    #[test]
    fn unsupported_options_are_rejected_before_they_are_stored() {
        let err = assert_storable(&DomainConfigOption::new(
            DomainConfigGroupName::Ldap,
            "bind_dn",
            "cn=admin",
        ))
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "option bind_dn in group ldap is not supported for domain specific configurations"
        );
        assert!(
            assert_storable(&DomainConfigOption::new(
                DomainConfigGroupName::Ldap,
                "password",
                "s3cr3t"
            ))
            .is_ok()
        );
    }

    #[test]
    fn values_an_option_cannot_hold_are_rejected_before_they_are_stored() {
        // Storing this would fail every later read of the domain, not just a
        // read of the option.
        let err = assert_storable(&DomainConfigOption::new(
            DomainConfigGroupName::Ldap,
            "page_size",
            "a lot",
        ))
        .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("invalid value for option page_size in group ldap"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn values_an_option_can_hold_are_accepted_in_every_spelling() {
        for value in [
            DomainConfigValue::new(10),
            // The spelling a per-domain config file delivers.
            DomainConfigValue::from("10"),
        ] {
            assert_storable(&DomainConfigOption::new(
                DomainConfigGroupName::Ldap,
                "page_size",
                value,
            ))
            .unwrap();
        }
    }
}
