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
//! # Keystone configuration
//!
//! Parsing of the Keystone configuration file implementation.
use chrono::TimeDelta;
use serde::{Deserialize, Deserializer};

pub fn csv<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(String::deserialize(deserializer)?
        .split(',')
        .map(Into::into)
        .collect())
}

// /// Deserializes an i64 and interprets it as total SECONDS for
// /// chrono::TimeDelta.
// fn timedelta_from_seconds<'de, D>(deserializer: D) -> Result<TimeDelta,
// D::Error> where
//     D: Deserializer<'de>,
// {
//     // Read the input number from JSON as an i64
//     let seconds = i64::deserialize(deserializer)?;
//
//     // Convert the number into a TimeDelta representing seconds
//     TimeDelta::try_seconds(seconds)
//         .ok_or_else(|| serde::de::Error::custom("TimeDelta overflow for
// seconds")) }

/// Deserializes an `Option<i64>` and interprets `Some(i64)` as total SECONDS
/// for TimeDelta.
pub fn optional_timedelta_from_seconds<'de, D>(
    deserializer: D,
) -> Result<Option<TimeDelta>, D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize the field content into Option<i64>.
    // Serde handles 'null' or an absent field by returning None here.
    let seconds_opt: Option<i64> = Option::deserialize(deserializer)?;

    match seconds_opt {
        // If a number was present, convert it to TimeDelta and wrap it in Some.
        Some(seconds) => TimeDelta::try_seconds(seconds)
            .map(Some) // Map TimeDelta to Some(TimeDelta)
            .ok_or_else(|| serde::de::Error::custom("TimeDelta overflow for optional seconds")),

        // If None was present (null or missing field), return Ok(None).
        None => Ok(None),
    }
}

pub fn default_sql_driver() -> String {
    "sql".into()
}
