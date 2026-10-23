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
use openstack_keystone_core::oauth2_client::dpop::{
    DpopProofContext, access_token_hash, jwk_thumbprint, verify_dpop_proof,
};
use url::Url;

// The `DPoP` header (ADR 0043 §2) is attacker-controlled text that the token
// endpoint and the resource side parse before the client is authenticated:
// a compact JWS whose header carries a `jwk` that is turned into a decoding
// key and an RFC 7638 thumbprint, with claims read before the signature is
// checked. None of it may panic on any input. The input is split at the
// first NUL byte into the proof and an access token, so the `ath` path is
// reached as well.
fuzz_target!(|data: &[u8]| {
    let (proof, token) = match data.iter().position(|b| *b == 0) {
        Some(at) => (&data[..at], Some(&data[at + 1..])),
        None => (data, None),
    };
    let Ok(proof) = std::str::from_utf8(proof) else {
        return;
    };
    let token = token.and_then(|t| std::str::from_utf8(t).ok());

    let Ok(uri) = Url::parse("https://ks.example/v4/oauth2/d1/token") else {
        return;
    };
    let nonces = ["a-nonce".to_string()];
    for accepted_nonces in [None, Some(&nonces[..])] {
        let _ = verify_dpop_proof(
            proof,
            &DpopProofContext {
                access_token: token,
                accepted_nonces,
                max_skew_secs: 60,
                method: "POST",
                now: 1_700_000_000,
                uri: &uri,
            },
        );
    }
    if let Some(token) = token {
        let _ = access_token_hash(token);
    }
    // The thumbprint is also computed from a `jwk` object on its own.
    if let Ok(serde_json::Value::Object(jwk)) = serde_json::from_str(proof) {
        let _ = jwk_thumbprint(&jwk);
    }
});
