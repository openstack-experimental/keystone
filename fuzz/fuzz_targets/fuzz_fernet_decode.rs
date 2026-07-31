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
use openstack_keystone_token_driver_fernet::fuzz_decode;

// Targets the MessagePack payload decoder that every Fernet token's
// decrypted body is parsed by (`FernetTokenProvider::decode` in
// `crates/token-driver-fernet/src/lib.rs`, reached from `decrypt` after
// Fernet's AEAD decrypt succeeds). It's a hand-rolled binary decoder over
// 11 payload shapes, exactly the kind of parser that hides
// out-of-bounds/panic bugs behind combinations unit tests don't happen to
// hit. Fuzzing post-AEAD-decrypt bytes directly (rather than the base64
// ciphertext through `decrypt`) is deliberate: without a valid Fernet key
// a fuzzer can't forge ciphertext that passes AEAD authentication, so it
// would never reach this parser at all.
fuzz_target!(|data: &[u8]| {
    let _ = fuzz_decode(data);
});
