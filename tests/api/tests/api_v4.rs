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
//! Keystone API v4 functional tests.
//!
//! This suite can not be executed against python Keystone.

mod api_v4 {
    mod api_key;
    mod audit;
    mod auth;
    mod federation;
    mod identity;
    mod mapping;
    mod oauth2;
    mod observability;
    mod role;
    mod role_assignment;
    mod scim_realm;
    mod token_restriction;
    mod webauthn;
}
