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
//! SoftHSM2-backed integration test for [`Pkcs11Kek`] (ADR 0016-v2 §2.5.1,
//! implementation plan step 3/6).
//!
//! Requires a SoftHSM2 module to be installed (`apt-get install softhsm2`,
//! same install step CI already runs for SPIRE). The module path is taken
//! from `TEST_PKCS11_MODULE` if set — matching the `cryptoki` crate's own
//! convention — otherwise the common Debian/Ubuntu path is tried.
//!
//! Each test initializes its own token in an isolated temp directory and
//! runs its whole body under `temp_env::with_var("SOFTHSM2_CONF", ...)`,
//! which serializes access to that process-global variable across the crate
//! (`temp_env` internally locks) so tests can still run concurrently without
//! clobbering each other's token directory.

use std::path::PathBuf;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use openstack_keystone_storage_crypto::error::CryptoError;
use openstack_keystone_storage_crypto::kek::KekProvider;
use openstack_keystone_storage_crypto_pkcs11::{Pkcs11Kek, Pkcs11KekParams, SlotSelector};
use tempfile::TempDir;

const SO_PIN: &str = "1234567890";
const USER_PIN: &str = "fedcba0987";
const TOKEN_LABEL: &str = "keystone-test";

fn module_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("TEST_PKCS11_MODULE") {
        return Some(PathBuf::from(p));
    }
    [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

/// `Result::unwrap()`/`expect()` are denied by the crate's clippy lints for
/// `#[test]`-attributed functions (matched by name/attribute), but these
/// setup helpers aren't themselves `#[test]` functions, so clippy doesn't
/// recognize them as test code. Panicking on setup failure is still exactly
/// what's wanted here — this just spells it without the denied methods.
fn ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(v) => v,
        Err(e) => panic!("{context}: {e}"),
    }
}

fn skip_without_softhsm() -> bool {
    if module_path().is_none() {
        eprintln!(
            "skipping: no SoftHSM2 module found (set TEST_PKCS11_MODULE or `apt-get install softhsm2`)"
        );
        return true;
    }
    false
}

/// A freshly initialized SoftHSM2 token, isolated in its own temp directory.
struct TestToken {
    module: PathBuf,
}

impl TestToken {
    /// Initialize a new token (SO PIN + user PIN set) inside `dir`.
    /// Must be called with `SOFTHSM2_CONF` already pointed at a config file
    /// under `dir`.
    fn init(module: PathBuf) -> Self {
        let pkcs11 = ok(Pkcs11::new(&module), "load module");
        ok(
            pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)),
            "initialize",
        );
        let slot = ok(pkcs11.get_slots_with_token(), "slots")[0];
        ok(
            pkcs11.init_token(slot, &AuthPin::new(SO_PIN.into()), TOKEN_LABEL),
            "init token",
        );
        {
            let session = ok(pkcs11.open_rw_session(slot), "so session");
            ok(
                session.login(UserType::So, Some(&AuthPin::new(SO_PIN.into()))),
                "so login",
            );
            ok(
                session.init_pin(&AuthPin::new(USER_PIN.into())),
                "init user pin",
            );
        }
        Self { module }
    }

    fn open(
        &self,
        key_label: &str,
        pin: &[u8],
        auto_generate: bool,
    ) -> Result<Pkcs11Kek, CryptoError> {
        Pkcs11Kek::open(Pkcs11KekParams {
            module_path: &self.module,
            slot: SlotSelector::Label(TOKEN_LABEL.into()),
            key_label,
            pin,
            auto_generate,
        })
    }
}

/// Set up an isolated SoftHSM2 token directory/config, run `f` with
/// `SOFTHSM2_CONF` pointed at it for the duration, and tear down afterwards.
/// Returns `None` if no SoftHSM2 module is available (caller should treat
/// that as a skipped test).
fn with_token<R>(f: impl FnOnce(&TestToken) -> R) -> Option<R> {
    let module = module_path()?;
    let dir = ok(TempDir::new(), "tempdir");
    let token_dir = dir.path().join("tokens");
    ok(std::fs::create_dir_all(&token_dir), "mkdir tokens");
    let conf_path = dir.path().join("softhsm2.conf");
    ok(
        std::fs::write(
            &conf_path,
            format!("directories.tokendir = {}\n", token_dir.display()),
        ),
        "write conf",
    );

    let result = temp_env::with_var("SOFTHSM2_CONF", Some(conf_path.as_os_str()), || {
        let token = TestToken::init(module);
        f(&token)
    });
    Some(result)
}

#[test]
fn test_wrap_unwrap_roundtrip() {
    if skip_without_softhsm() {
        return;
    }
    with_token(|token| {
        let kek = token
            .open("roundtrip-kek", USER_PIN.as_bytes(), true)
            .expect("open KEK");

        let dek = [0xABu8; 32];
        let wrapped = kek.wrap_dek(&dek).expect("wrap");
        assert_eq!(wrapped.len(), 60); // 12-byte nonce + 32-byte ciphertext + 16-byte tag
        let unwrapped = kek.unwrap_dek(&wrapped).expect("unwrap");
        assert_eq!(unwrapped.as_ref(), &dek);
    });
}

#[test]
fn test_wrap_produces_different_nonces() {
    if skip_without_softhsm() {
        return;
    }
    with_token(|token| {
        let kek = token
            .open("nonce-kek", USER_PIN.as_bytes(), true)
            .expect("open KEK");

        let dek = [0xCDu8; 32];
        let w1 = kek.wrap_dek(&dek).expect("wrap 1");
        let w2 = kek.wrap_dek(&dek).expect("wrap 2");
        assert_ne!(w1, w2);
        // Same DEK, different nonces -> different ciphertext, but both
        // unwrap back to the same plaintext.
        assert_eq!(kek.unwrap_dek(&w1).expect("unwrap 1").as_ref(), &dek);
        assert_eq!(kek.unwrap_dek(&w2).expect("unwrap 2").as_ref(), &dek);
    });
}

#[test]
fn test_unwrap_tampered_tag_fails() {
    if skip_without_softhsm() {
        return;
    }
    with_token(|token| {
        let kek = token
            .open("tamper-kek", USER_PIN.as_bytes(), true)
            .expect("open KEK");

        let dek = [0x11u8; 32];
        let mut wrapped = kek.wrap_dek(&dek).expect("wrap");
        *wrapped.last_mut().expect("non-empty") ^= 0xFF;
        assert!(matches!(
            kek.unwrap_dek(&wrapped),
            Err(CryptoError::AesDecrypt)
        ));
    });
}

#[test]
fn test_unwrap_tampered_ciphertext_fails() {
    if skip_without_softhsm() {
        return;
    }
    with_token(|token| {
        let kek = token
            .open("tamper-ct-kek", USER_PIN.as_bytes(), true)
            .expect("open KEK");

        let dek = [0x22u8; 32];
        let mut wrapped = kek.wrap_dek(&dek).expect("wrap");
        wrapped[20] ^= 0xFF; // inside the ciphertext region
        assert!(matches!(
            kek.unwrap_dek(&wrapped),
            Err(CryptoError::AesDecrypt)
        ));
    });
}

#[test]
fn test_open_reuses_existing_key_across_sessions() {
    if skip_without_softhsm() {
        return;
    }
    with_token(|token| {
        let kek1 = token
            .open("reuse-kek", USER_PIN.as_bytes(), true)
            .expect("open first session");

        let dek = [0x33u8; 32];
        let wrapped = kek1.wrap_dek(&dek).expect("wrap with first session");
        drop(kek1);

        // A second provider opened against the same token/label must
        // resolve to the same underlying key object and be able to unwrap
        // the first session's ciphertext.
        let kek2 = token
            .open("reuse-kek", USER_PIN.as_bytes(), false)
            .expect("reopen without auto_generate");
        let unwrapped = kek2
            .unwrap_dek(&wrapped)
            .expect("unwrap with second session");
        assert_eq!(unwrapped.as_ref(), &dek);
    });
}

#[test]
fn test_open_wrong_pin_fails() {
    if skip_without_softhsm() {
        return;
    }
    with_token(|token| {
        // Establish the key first so a wrong PIN is the only failure mode.
        token
            .open("wrong-pin-kek", USER_PIN.as_bytes(), true)
            .expect("provision key");

        let result = token.open("wrong-pin-kek", b"not-the-pin", false);
        assert!(matches!(result, Err(CryptoError::Pkcs11(_))));
    });
}

#[test]
fn test_open_missing_key_without_auto_generate_fails() {
    if skip_without_softhsm() {
        return;
    }
    with_token(|token| {
        let result = token.open("nobody-generated-this-label", USER_PIN.as_bytes(), false);
        assert!(matches!(result, Err(CryptoError::Pkcs11(_))));
    });
}

#[test]
fn test_open_slot_by_label_matches_slot_by_id() {
    if skip_without_softhsm() {
        return;
    }
    // SoftHSM only tolerates one live `C_Initialize`'d context per process
    // for a given module, so the two providers are opened sequentially
    // (the first is dropped, closing its session, before the second opens)
    // rather than held open simultaneously.
    with_token(|token| {
        let wrapped = {
            let kek_by_label = token
                .open("slot-id-kek", USER_PIN.as_bytes(), true)
                .expect("open by label");
            let dek = [0x44u8; 32];
            kek_by_label.wrap_dek(&dek).expect("wrap via label session")
        };

        // Slot ids handed out by SoftHSM are only valid within the
        // `C_Initialize` session that produced them, so re-resolve the id
        // fresh here (the label-keyed session above has already been
        // dropped and finalized) rather than reusing the id captured during
        // `TestToken::init`.
        let slot_id = {
            let pkcs11 = Pkcs11::new(&token.module).expect("load module for slot lookup");
            pkcs11
                .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
                .expect("initialize for slot lookup");
            pkcs11.get_slots_with_token().expect("slots")[0].id()
        };

        let kek_by_id = Pkcs11Kek::open(Pkcs11KekParams {
            module_path: &token.module,
            slot: SlotSelector::Id(slot_id),
            key_label: "slot-id-kek",
            pin: USER_PIN.as_bytes(),
            auto_generate: false,
        })
        .expect("open by slot id");

        let unwrapped = kek_by_id
            .unwrap_dek(&wrapped)
            .expect("unwrap via id session");
        assert_eq!(unwrapped.as_ref(), &[0x44u8; 32]);
    });
}
