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

/// Merge update `extra` properties onto the currently stored ones, following
/// the Python keystone semantics.
///
/// `extra` is a free-form bag of additional properties. Rather than replacing
/// it wholesale on update (which would drop every property the caller did not
/// resend), the currently stored properties are used as the base and the
/// supplied `updates` are applied on top of them:
///
/// - a key with a non-null value overwrites (or adds) that key, and
/// - a key whose new value is JSON `null` unsets (removes) that key.
///
/// Properties the caller did not mention are left untouched.
///
/// This runs in the provider layer so the value handed to the backend driver
/// (and recorded in traces) is exactly what gets persisted; the driver is only
/// responsible for storing it.
///
/// # Parameters
/// - `existing`: The currently stored `extra` value, if any. Anything that is
///   not a JSON object is treated as an empty base.
/// - `updates`: The `extra` properties supplied in the update request.
///
/// # Returns
/// The merged `extra` properties.
pub fn merge_extra(
    existing: Option<&Value>,
    updates: HashMap<String, Value>,
) -> HashMap<String, Value> {
    let mut merged: HashMap<String, Value> = match existing {
        Some(Value::Object(map)) => map.clone().into_iter().collect(),
        _ => HashMap::new(),
    };

    for (key, value) in updates {
        if value.is_null() {
            merged.remove(&key);
        } else {
            merged.insert(key, value);
        }
    }

    merged
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
        let existing = json!({"keep": "me", "change": "old"});
        let updates = HashMap::from([("change".to_string(), json!("new"))]);

        let merged = merge_extra(Some(&existing), updates);
        assert_eq!(merged.get("keep"), Some(&json!("me")));
        assert_eq!(merged.get("change"), Some(&json!("new")));
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_merge_extra_adds_new_keys() {
        let existing = json!({"a": 1});
        let updates = HashMap::from([("b".to_string(), json!(2))]);

        let merged = merge_extra(Some(&existing), updates);
        assert_eq!(merged.get("a"), Some(&json!(1)));
        assert_eq!(merged.get("b"), Some(&json!(2)));
    }

    #[test]
    fn test_merge_extra_null_unsets_key() {
        // A null value removes the key from the stored properties.
        let existing = json!({"drop": "me", "keep": "yes"});
        let updates = HashMap::from([("drop".to_string(), Value::Null)]);

        let merged = merge_extra(Some(&existing), updates);
        assert!(!merged.contains_key("drop"));
        assert_eq!(merged.get("keep"), Some(&json!("yes")));
    }

    #[test]
    fn test_merge_extra_null_on_missing_key_is_noop() {
        let existing = json!({"a": 1});
        let updates = HashMap::from([("missing".to_string(), Value::Null)]);

        let merged = merge_extra(Some(&existing), updates);
        assert_eq!(merged.get("a"), Some(&json!(1)));
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn test_merge_extra_handles_non_object_or_missing_existing() {
        // Anything that is not a JSON object is treated as an empty base.
        for existing in [None, Some(json!(null)), Some(json!("scalar"))] {
            let updates = HashMap::from([("a".to_string(), json!(1))]);
            let merged = merge_extra(existing.as_ref(), updates);
            assert_eq!(merged.get("a"), Some(&json!(1)));
            assert_eq!(merged.len(), 1);
        }
    }
}
