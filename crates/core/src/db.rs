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
//! # Internal tools for the database handling

use std::collections::HashMap;

use sea_orm::{ConnectionTrait, EntityTrait, Schema, sea_query::IndexCreateStatement};
use serde_json::Value;

use crate::error::{DatabaseError, DbContextExt};

/// Merge update `extra` properties into the currently stored `extra` blob,
/// following the Python keystone semantics.
///
/// The `extra` field is a JSON object serialized as a string in the database.
/// Rather than replacing it wholesale on update (which would drop every
/// property the caller did not resend), the existing object is used as the base
/// and the supplied `updates` are applied on top of it:
///
/// - a key with a non-null value overwrites (or adds) that key, and
/// - a key whose new value is JSON `null` unsets (removes) that key.
///
/// This preserves untouched properties while still allowing individual
/// properties to be cleared.
///
/// # Parameters
/// - `existing`: The currently stored `extra` JSON string, if any.
/// - `updates`: The `extra` properties supplied in the update request.
///
/// # Returns
/// A `Result` containing the merged `extra` serialized as a JSON string, or a
/// `serde_json::Error` if the existing blob could not be parsed.
pub fn merge_extra(
    existing: Option<&str>,
    updates: &HashMap<String, Value>,
) -> Result<String, serde_json::Error> {
    let mut merged: serde_json::Map<String, Value> = match existing {
        Some(raw) if !raw.is_empty() && raw != "{}" => match serde_json::from_str::<Value>(raw)? {
            Value::Object(map) => map,
            _ => serde_json::Map::new(),
        },
        _ => serde_json::Map::new(),
    };

    for (key, value) in updates {
        if value.is_null() {
            merged.remove(key);
        } else {
            merged.insert(key.clone(), value.clone());
        }
    }

    serde_json::to_string(&Value::Object(merged))
}

/// Create the table in the database with directly related types and indexes.
pub async fn create_table<C, E>(conn: &C, schema: &Schema, entity: E) -> Result<(), DatabaseError>
where
    C: ConnectionTrait,
    E: EntityTrait,
{
    // Create types before the table
    for ttype in schema.create_enum_from_entity(entity) {
        conn.execute(conn.get_database_backend().build(&ttype))
            .await
            .context("creating types")?;
    }
    // Create the table
    conn.execute(
        conn.get_database_backend()
            .build(&schema.create_table_from_entity(entity)),
    )
    .await
    .context("creating table")?;
    // Create related indexes
    for tidx in schema.create_index_from_entity(entity) {
        conn.execute(conn.get_database_backend().build(&tidx))
            .await
            .context("creating table indexes")?;
    }
    Ok(())
}

/// Create the index.
pub async fn create_index<C>(conn: &C, index: IndexCreateStatement) -> Result<(), DatabaseError>
where
    C: ConnectionTrait,
{
    conn.execute(conn.get_database_backend().build(&index))
        .await
        .context("creating the index")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_merge_extra_preserves_existing_keys() {
        // A key absent from the update must survive the merge.
        let existing = r#"{"keep":"me","change":"old"}"#;
        let updates = HashMap::from([("change".to_string(), json!("new"))]);

        let merged: Value =
            serde_json::from_str(&merge_extra(Some(existing), &updates).unwrap()).unwrap();
        assert_eq!(merged, json!({"keep": "me", "change": "new"}));
    }

    #[test]
    fn test_merge_extra_adds_new_keys() {
        let existing = r#"{"a":1}"#;
        let updates = HashMap::from([("b".to_string(), json!(2))]);

        let merged: Value =
            serde_json::from_str(&merge_extra(Some(existing), &updates).unwrap()).unwrap();
        assert_eq!(merged, json!({"a": 1, "b": 2}));
    }

    #[test]
    fn test_merge_extra_null_unsets_key() {
        // A null value removes the key from the stored blob.
        let existing = r#"{"drop":"me","keep":"yes"}"#;
        let updates = HashMap::from([("drop".to_string(), Value::Null)]);

        let merged: Value =
            serde_json::from_str(&merge_extra(Some(existing), &updates).unwrap()).unwrap();
        assert_eq!(merged, json!({"keep": "yes"}));
    }

    #[test]
    fn test_merge_extra_null_on_missing_key_is_noop() {
        let existing = r#"{"a":1}"#;
        let updates = HashMap::from([("missing".to_string(), Value::Null)]);

        let merged: Value =
            serde_json::from_str(&merge_extra(Some(existing), &updates).unwrap()).unwrap();
        assert_eq!(merged, json!({"a": 1}));
    }

    #[test]
    fn test_merge_extra_handles_empty_or_missing_existing() {
        let updates = HashMap::from([("a".to_string(), json!(1))]);

        for existing in [None, Some(""), Some("{}")] {
            let merged: Value =
                serde_json::from_str(&merge_extra(existing, &updates).unwrap()).unwrap();
            assert_eq!(merged, json!({"a": 1}));
        }
    }
}
