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
//! `/SCIM/v2` live-HTTP, live-OPA functional tests (ADR 0021, ADR 0024).
//!
//! A sibling of `/v3`/`/v4`, not nested under `api_v4/`: the SCIM ingress
//! surface is a bespoke bearer-token protocol (ADR 0021 §4, Sub-Router
//! Isolation), not part of the OpenStack-catalog API. Each submodule here is
//! the live-HTTP-and-live-OPA counterpart of an existing mocked-state
//! handler test file under `crates/keystone/src/scim/`.

mod scim_v2 {
    mod common;
    mod etag;
    mod filter;
    mod group;
    mod patch;
    mod user;
}
