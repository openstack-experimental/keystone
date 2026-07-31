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

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use openstack_keystone_core::credential::ec2_signature::{
    Ec2SignatureVersion, detect_signature_version, generate_signature, validate_timestamp,
    verify_signature,
};
use openstack_keystone_core_types::credential::Ec2SignatureRequest;

// `Ec2SignatureRequest` carries client-controlled `access`/`signature`/
// `host`/`verb`/`path`/`params`/`headers`/`body_hash` straight from
// `POST /v3/ec2tokens` (ADR 0019 §5) into multi-version (v0/v1/v2/v4)
// string-to-sign canonicalization: sorting, case folding, percent-encoding,
// `Authorization`-header component parsing, and byte-offset string slicing
// (`credential.split('/')`, `value.find(':')`). That combination of hand-
// written string surgery over attacker-shaped headers/params is exactly the
// class of code fuzzing tends to find panics in that a manual read misses,
// even though the crypto comparison itself is constant-time and correct by
// inspection. This is a structured (`arbitrary`-derived) harness rather than
// a flat byte slice since `Ec2SignatureRequest` is a multi-field struct, not
// a single blob to parse.
fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(req) = Ec2SignatureRequest::arbitrary(&mut u) else {
        return;
    };
    let Ok(secret) = String::arbitrary(&mut u) else {
        return;
    };

    let _ = detect_signature_version(&req);
    let _ = verify_signature(&secret, &req);
    let _ = validate_timestamp(&req, 300);

    // Drive every version's string-to-sign derivation directly, regardless
    // of what `detect_signature_version` guessed from this particular
    // input, so fuzzing isn't gated on also getting the version-detection
    // hints right.
    for version in [
        Ec2SignatureVersion::V0,
        Ec2SignatureVersion::V1,
        Ec2SignatureVersion::V2,
        Ec2SignatureVersion::V4,
    ] {
        let _ = generate_signature(&secret, version, &req);
    }
});
