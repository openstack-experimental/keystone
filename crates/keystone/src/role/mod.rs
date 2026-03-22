// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! # Role provider
//!
//! Role provider provides possibility to manage roles (part of RBAC).
//!
//! Following Keystone concepts are covered by the provider:
//!
//! ## Role inference
//!
//! Roles in Keystone may imply other roles building an inference chain. For
//! example a role `manager` can imply the `member` role, which in turn implies
//! the `reader` role. As such with a single assignment of the `manager` role
//! the user will automatically get `manager`, `member` and `reader` roles. This
//! helps limiting number of necessary direct assignments.
//!
//! ## Role
//!
//! A personality with a defined set of user rights and privileges to perform a
//! specific set of operations. The Identity service issues a token to a user
//! that includes a list of roles. When a user calls a service, that service
//! interprets the user role set, and determines to which operations or
//! resources each role grants access.

pub use openstack_keystone_core::role::*;
