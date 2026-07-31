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
#![no_main]

use libfuzzer_sys::fuzz_target;
use openstack_keystone_auth_plugin_runtime::decode_and_validate_route_response;

// Host-side decoder for a `route`-mode WASM plugin's `route` response (ADR
// 0025 §4/§7) — same untrusted-guest-output trust class as
// `fuzz_auth_contract_response`, applied to `RouteResponse` instead of
// `AuthPluginResponse`.
fuzz_target!(|data: &[u8]| {
    let _ = decode_and_validate_route_response(data);
});
