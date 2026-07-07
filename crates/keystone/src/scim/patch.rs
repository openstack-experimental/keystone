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
//! # SCIM `PATCH` request shape and path validation (ADR 0024 §5.C)
//!
//! `Operations: [{op, path, value}]` is accepted only for a fixed,
//! per-resource allowlist of top-level scalar `path` targets. Anything else
//! -- a complex filter expression (`emails[type eq "work"].value`), an
//! array-index path, or an omitted `path` -- is rejected with
//! `400 Bad Request` (`scimType: "invalidPath"`) before any attribute is
//! touched. Resource-specific application of a validated operation list
//! lives in `scim::user::patch` / `scim::group::patch`.

use serde::Deserialize;
use serde_json::Value;

use crate::scim::error::ScimApiError;

/// ADR 0024 §5.C User `path` allowlist (lowercased).
pub const USER_PATCH_PATHS: &[&str] = &[
    "active",
    "username",
    "displayname",
    "externalid",
    "name.givenname",
    "name.familyname",
];

/// ADR 0024 §5.C Group `path` allowlist (lowercased). `members` is
/// add/remove only -- enforced separately in `scim::group::patch`, not by
/// this table.
pub const GROUP_PATCH_PATHS: &[&str] = &["displayname", "externalid", "members"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOp {
    Add,
    Replace,
    Remove,
}

impl PatchOp {
    pub fn parse(token: &str) -> Option<Self> {
        match token.to_ascii_lowercase().as_str() {
            "add" => Some(Self::Add),
            "replace" => Some(Self::Replace),
            "remove" => Some(Self::Remove),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimPatchOperation {
    pub op: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub value: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScimPatchRequest {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<ScimPatchOperation>,
}

/// A validated `ScimPatchOperation`, its `path` lowercased and its `op`
/// resolved to a [`PatchOp`].
pub struct ValidatedPatchOp {
    pub op: PatchOp,
    pub path: String,
    pub value: Value,
}

/// Validate `Operations[].{op,path}` against `allowed_paths`, in request
/// order. Rejects the whole request on the first violation -- partial
/// application of an otherwise-invalid PATCH would leave the resource in a
/// state the client never asked for.
pub fn validate_patch(
    req: &ScimPatchRequest,
    allowed_paths: &[&str],
) -> Result<Vec<ValidatedPatchOp>, ScimApiError> {
    if req.operations.is_empty() {
        return Err(ScimApiError::InvalidPath(
            "Operations must not be empty".to_string(),
        ));
    }
    req.operations
        .iter()
        .map(|raw| {
            let Some(path) = &raw.path else {
                return Err(ScimApiError::InvalidPath(
                    "path is required for every operation".to_string(),
                ));
            };
            let path = path.to_ascii_lowercase();
            if !allowed_paths.contains(&path.as_str()) {
                return Err(ScimApiError::InvalidPath(format!(
                    "path `{path}` is not patchable"
                )));
            }
            let Some(op) = PatchOp::parse(&raw.op) else {
                return Err(ScimApiError::InvalidPath(format!(
                    "unsupported op `{}`",
                    raw.op
                )));
            };
            Ok(ValidatedPatchOp {
                op,
                path,
                value: raw.value.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(op: &str, path: &str, value: Value) -> ScimPatchOperation {
        ScimPatchOperation {
            op: op.to_string(),
            path: Some(path.to_string()),
            value,
        }
    }

    #[test]
    fn test_validate_accepts_allowed_path() {
        let req = ScimPatchRequest {
            schemas: vec![],
            operations: vec![op("replace", "active", Value::Bool(false))],
        };
        let validated = validate_patch(&req, USER_PATCH_PATHS).unwrap();
        assert_eq!(validated.len(), 1);
        assert_eq!(validated[0].path, "active");
        assert!(matches!(validated[0].op, PatchOp::Replace));
    }

    #[test]
    fn test_validate_rejects_missing_path() {
        let req = ScimPatchRequest {
            schemas: vec![],
            operations: vec![ScimPatchOperation {
                op: "replace".to_string(),
                path: None,
                value: Value::Null,
            }],
        };
        let result = validate_patch(&req, USER_PATCH_PATHS);
        assert!(matches!(result, Err(ScimApiError::InvalidPath(_))));
    }

    #[test]
    fn test_validate_rejects_complex_filter_path() {
        let req = ScimPatchRequest {
            schemas: vec![],
            operations: vec![op(
                "replace",
                r#"emails[type eq "work"].value"#,
                Value::String("a@b.com".to_string()),
            )],
        };
        let result = validate_patch(&req, USER_PATCH_PATHS);
        assert!(matches!(result, Err(ScimApiError::InvalidPath(_))));
    }

    #[test]
    fn test_validate_rejects_unsupported_op() {
        let req = ScimPatchRequest {
            schemas: vec![],
            operations: vec![op("move", "active", Value::Bool(true))],
        };
        let result = validate_patch(&req, USER_PATCH_PATHS);
        assert!(matches!(result, Err(ScimApiError::InvalidPath(_))));
    }

    #[test]
    fn test_validate_rejects_empty_operations() {
        let req = ScimPatchRequest {
            schemas: vec![],
            operations: vec![],
        };
        let result = validate_patch(&req, USER_PATCH_PATHS);
        assert!(matches!(result, Err(ScimApiError::InvalidPath(_))));
    }
}
