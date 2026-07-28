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
//! # Policy store provider
//!
//! Storage for the legacy `/v3/policies` API: opaque, arbitrarily serialized
//! policy documents that *remote* services fetch and interpret themselves.
//!
//! This has nothing to do with authorization in this service. Keystone's own
//! access control is decided by OPA/Rego (`crate::policy` in the `core`
//! crate, `policy/**/*.rego` in the repository root); a `Policy` here is
//! inert data Keystone never reads. Python keystone's api-ref marks the API
//! deprecated ("Keystone is not a policy management service") and it is
//! implemented purely for API compatibility.
mod error;
mod policy;

pub use error::*;
pub use policy::*;
