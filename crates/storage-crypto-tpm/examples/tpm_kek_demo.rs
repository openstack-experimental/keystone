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
//! Runnable sample for the TPM 2.0 KEK provider (ADR 0016-v2 §2.5.2,
//! implementation plan step 4).
//!
//! This is a doc sample, not a CI-gated test (see the implementation plan's
//! "Test/sample scope" decision) — CI only compiles it to catch rot, it is
//! not executed. Run it locally against a software TPM:
//!
//! ```sh
//! # 1. Start a software TPM (swtpm) listening on the default MSSIM-style
//! #    port pair used below.
//! mkdir -p /tmp/swtpm-state
//! swtpm socket --tpmstate dir=/tmp/swtpm-state \
//!     --ctrl type=tcp,port=2322 --server type=tcp,port=2321 \
//!     --tpm2 --flags not-need-init &
//!
//! # 2. Send TPM2_Startup (tpm2-tools' tpm2_startup, or any TSS client).
//! TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321" tpm2_startup -c
//!
//! # 3. Run this example. TPM_KEK_CONTEXT_FILE defaults to a temp path if
//! #    unset; delete it between runs to re-provision fresh keys.
//! cargo run -p openstack-keystone-storage-crypto-tpm --example tpm_kek_demo
//! ```
//!
//! First run creates the AES + HMAC child keys (`auto_generate: true`) and
//! saves their blobs to the context file pair; subsequent runs reload the
//! same keys and prove a DEK wrapped by one process invocation unwraps
//! correctly in the next.

use std::path::PathBuf;

use openstack_keystone_storage_crypto::kek::KekProvider;
use openstack_keystone_storage_crypto_tpm::{KeyReference, TpmKek, TpmKekParams};

#[allow(clippy::print_stdout)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tcti = std::env::var("TPM_KEK_TCTI")
        .unwrap_or_else(|_| "swtpm:host=127.0.0.1,port=2321".to_string());
    let context_file = std::env::var("TPM_KEK_CONTEXT_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("keystone-tpm-kek-demo.ctx"));

    println!("connecting to TPM via TCTI {tcti:?}");
    println!("AES key context file:  {}", context_file.display());
    println!("HMAC key context file: {}.hmac", context_file.display());

    let already_provisioned = context_file.exists();
    let kek = TpmKek::open(TpmKekParams {
        tcti: &tcti,
        key_reference: KeyReference::ContextFile(context_file.clone()),
        auth: None,
        auto_generate: true,
    })?;
    println!(
        "{} KEK (create the files with `rm {} {}.hmac` to reset)",
        if already_provisioned {
            "loaded existing"
        } else {
            "provisioned new"
        },
        context_file.display(),
        context_file.display(),
    );

    let dek = [0x42u8; 32];
    let wrapped = kek.wrap_dek(&dek)?;
    println!(
        "wrapped a 32-byte DEK into {} bytes: {}",
        wrapped.len(),
        hex_encode(&wrapped)
    );

    let unwrapped = kek.unwrap_dek(&wrapped)?;
    assert_eq!(unwrapped.as_ref(), &dek, "round-trip must recover the DEK");
    println!("unwrapped successfully — round-trip verified");

    let mut tampered = wrapped.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 0xFF;
    }
    match kek.unwrap_dek(&tampered) {
        Err(e) => println!("tampered ciphertext correctly rejected: {e}"),
        Ok(_) => return Err("tampered ciphertext was NOT rejected".into()),
    }

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
