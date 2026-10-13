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
//! `/v4/oauth2/*` functional tests (ADR 0026).

mod authorize_browser;
mod authorize_logout;
mod authorize_mfa;
mod authorize_sso;
mod clients;
mod consent_memory;
mod cross_domain;
mod device_authorization;
mod device_browser;
mod device_regressions;
mod discovery;
mod introspect;
mod jwks_revocation;
mod key_rotation;
mod logout;
mod revoke;
mod token_client_credentials;
mod token_device_grant;
mod token_exchange;
mod token_refresh;
mod ui_branding;
mod userinfo;
