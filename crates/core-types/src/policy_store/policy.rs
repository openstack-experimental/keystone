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

use derive_builder::Builder;
use serde_json::Value;
use validator::Validate;

use crate::error::BuilderError;

/// A stored policy document.
///
/// # Note on `Serialize`
///
/// This type deliberately does **not** derive `Serialize`. Handlers build the
/// OPA policy input from an explicit non-sensitive allowlist
/// (`policy_input()` in the `v3::policy` API module) rather than by
/// serializing this struct, and `blob`/`extra` hold arbitrary caller-supplied
/// JSON that must never reach the policy engine or its decision log. Not
/// having `Serialize` makes an accidental `json!({"policy": policy})` a
/// compile error instead of a silent leak.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Policy {
    /// Additional policy properties.
    #[builder(default)]
    pub extra: HashMap<String, Value>,

    /// The ID of the policy.
    #[validate(length(min = 1, max = 64))]
    pub id: String,

    /// The policy rule set itself, as an opaque serialized document.
    ///
    /// Modelled as an arbitrary JSON value rather than a `String` so rows
    /// written by python keystone before its schema constrained the API input
    /// to a string (object-valued blobs) still deserialize. The HTTP layer
    /// only ever accepts a string.
    #[builder(default)]
    pub blob: Value,

    /// The MIME media type of the serialized policy blob.
    ///
    /// Only length-capped, deliberately not `min = 1`: python keystone's
    /// schema is `{'type': 'string', 'maxLength': 255}`, so `type` is
    /// *required* but may legitimately be the empty string.
    #[validate(length(max = 255))]
    pub r#type: String,
}

/// Parameters for creating a new policy.
#[derive(Clone, Debug, Default, PartialEq, Validate)]
pub struct PolicyCreate {
    /// Additional policy properties.
    pub extra: HashMap<String, Value>,

    /// The ID of the policy.
    ///
    /// Always populated by the service layer before the backend is called, so
    /// the audit event carries the final identifier. The API layer never sets
    /// it: python keystone's `_assign_unique_id` discards any caller-supplied
    /// `id` on create, and so do we.
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,

    /// The policy rule set itself.
    pub blob: Value,

    /// The MIME media type of the serialized policy blob.
    ///
    /// Only length-capped, deliberately not `min = 1`: python keystone's
    /// schema is `{'type': 'string', 'maxLength': 255}`, so `type` is
    /// *required* but may legitimately be the empty string.
    #[validate(length(max = 255))]
    pub r#type: String,
}

/// Parameters for listing policies.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct PolicyListParameters {
    /// Pagination controls (limit/marker/page_reverse).
    #[builder(default)]
    pub pagination: crate::ListPagination,

    /// Filters the response by a MIME media type of the policy blob.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub r#type: Option<String>,
}

/// Fields that can be changed when updating a policy.
///
/// Each field is `None` when the caller did not provide it (leave unchanged)
/// and `Some(..)` to set a new value.
#[derive(Clone, Debug, Default, PartialEq, Validate)]
pub struct PolicyUpdate {
    /// Additional policy properties, *merged* into the stored `extra` (keys
    /// present here win; keys only present in the stored object survive).
    ///
    /// This mirrors python keystone's `update_policy`, which patches the old
    /// dict (`old_dict.update(policy)`) before writing it back. It is
    /// deliberately different from e.g. `RegionUpdate.extra`, which this
    /// codebase overwrites wholesale.
    pub extra: HashMap<String, Value>,

    /// New policy blob.
    pub blob: Option<Value>,

    /// New MIME media type of the serialized policy blob.
    ///
    /// See [`Policy::type`] on the absence of a minimum length.
    #[validate(length(max = 255))]
    pub r#type: Option<String>,
}
