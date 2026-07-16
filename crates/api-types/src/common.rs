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

use chrono::{DateTime, SecondsFormat, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::Serializer;

/// OpenStack clients (e.g. tempest, python-keystoneclient) parse timestamps
/// with `strptime` formats accepting at most 6 fractional-second digits
/// (`%Y-%m-%dT%H:%M:%S.%fZ`). `DateTime<Utc>`'s default serde impl emits full
/// nanosecond precision, which those clients cannot parse. Truncate to
/// microseconds on the wire to match the format Keystone has always produced.
pub(crate) fn serialize_datetime_micros<S>(
    dt: &DateTime<Utc>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&dt.to_rfc3339_opts(SecondsFormat::Micros, true))
}

pub(crate) fn serialize_optional_datetime_micros<S>(
    dt: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match dt {
        Some(dt) => serializer.serialize_some(&dt.to_rfc3339_opts(SecondsFormat::Micros, true)),
        None => serializer.serialize_none(),
    }
}

pub(crate) fn serialize_secret_string<S>(
    secret: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(secret.expose_secret())
}

pub(crate) fn serialize_optional_secret<S>(
    secret: &Option<SecretString>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match secret {
        Some(secret) => serializer.serialize_some(secret.expose_secret()),
        None => serializer.serialize_none(),
    }
}

pub(crate) fn serialize_nested_optional_secret<S>(
    secret: &Option<Option<SecretString>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match secret {
        Some(Some(secret)) => serializer.serialize_some(secret.expose_secret()),
        _ => serializer.serialize_none(),
    }
}

#[cfg(feature = "validate")]
pub(crate) fn validate_secret_length(
    secret: &SecretString,
    max: usize,
) -> Result<(), validator::ValidationError> {
    if secret.expose_secret().chars().count() <= max {
        Ok(())
    } else {
        Err(validator::ValidationError::new("length"))
    }
}

#[cfg(feature = "validate")]
pub(crate) fn validate_optional_secret_length(
    secret: &Option<SecretString>,
    max: usize,
) -> Result<(), validator::ValidationError> {
    match secret {
        Some(secret) => validate_secret_length(secret, max),
        None => Ok(()),
    }
}

#[cfg(feature = "validate")]
pub(crate) fn validate_nested_optional_secret_length(
    secret: &Option<Option<SecretString>>,
    max: usize,
) -> Result<(), validator::ValidationError> {
    match secret {
        Some(Some(secret)) => validate_secret_length(secret, max),
        _ => Ok(()),
    }
}
