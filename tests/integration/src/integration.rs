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
//! # Integration tests
//!
//! Test the functionality on the provider level (not through the API).

mod api_key;
mod application_credential;
mod assignment;
mod audit;
mod catalog;
mod common;
mod credential;
mod federation;
mod identity;
mod k8s_auth;
mod mapping;
mod oauth2_device_grant;
mod oauth2_emergency_rotation;
mod oauth2_key_janitor;
mod oauth2_session;
mod oauth2_token_exchange;
mod oauth2_token_verify;
mod resource;
mod revoke;
mod role;
mod scim_realm;
mod token;
mod trust;

#[macro_use]
mod macros;
