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
use openstack_keystone_auth_plugin_runtime::decode_and_validate_response;

// `decode_and_validate_response` is the host-side decoder for a `full_auth`
// -mode WASM auth plugin's `authenticate` response (ADR 0025 §7): raw bytes
// returned by an untrusted, possibly-compromised guest, parsed and
// bounds-checked before anything in it is trusted by the host. Every
// invocation of the plugin is pre-authentication (ADR 0025 §1 Threat
// Model, actor 2), so this is exactly the untrusted-input boundary named
// as "Gate F" in doc/src/contributor/security-review.md.
fuzz_target!(|data: &[u8]| {
    let _ = decode_and_validate_response(data);
});
