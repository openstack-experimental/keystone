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
//! # PKCS#11 KEK provider
//!
//! Implements [`Pkcs11Kek`], a [`KekProvider`] backed by a non-extractable
//! AES-256 key object on a PKCS#11 token (ADR 0016-v2 §2.5.1). Wrap/unwrap
//! use `CKM_AES_GCM` directly against the token key, producing the same
//! `[12-byte nonce][ciphertext][16-byte tag]` wire format [`EnvKek`] uses —
//! nothing downstream of [`KekProvider`] needs to know the DEK is wrapped by
//! an HSM rather than in-process.
//!
//! Kept in its own crate (not a module of `storage-crypto`) so the FFI-heavy
//! `cryptoki` dependency stays out of the crate that owns the workspace's
//! `unsafe_code = "deny"` core primitives — this crate itself never needs
//! `unsafe` (`cryptoki` is a safe wrapper over the C API).
//!
//! [`EnvKek`]: openstack_keystone_storage_crypto::kek::EnvKek

use std::path::Path;
use std::sync::Mutex;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use openstack_keystone_storage_crypto::error::CryptoError;
use openstack_keystone_storage_crypto::kek::KekProvider;
use rand::RngExt;
use zeroize::Zeroizing;

/// Associated data used for DEK wrapping, matching [`EnvKek`]'s binding
/// context so ciphertext produced by either provider is distinguishable only
/// by which KEK unwraps it, not by format.
///
/// [`EnvKek`]: openstack_keystone_storage_crypto::kek::EnvKek
const DEK_WRAP_AD: &[u8] = b"keystone-dek-wrap-v1";

/// Selects which token slot to open a session on.
#[derive(Debug, Clone)]
pub enum SlotSelector {
    /// Open the slot with this numeric id.
    Id(u64),
    /// Open the slot whose token label matches exactly.
    Label(String),
}

/// Parameters needed to open (and, if missing, provision) the PKCS#11 KEK.
pub struct Pkcs11KekParams<'a> {
    /// Path to the PKCS#11 module (`.so`) to `dlopen`.
    pub module_path: &'a Path,
    /// Which slot to open a session on.
    pub slot: SlotSelector,
    /// `CKA_LABEL` of the AES key object to use as the KEK.
    pub key_label: &'a str,
    /// User PIN for the token, as raw bytes (must be valid UTF-8).
    pub pin: &'a [u8],
    /// If no key with `key_label` exists on the token, generate a new
    /// non-extractable AES-256 key with that label instead of failing.
    ///
    /// Left as an explicit constructor parameter rather than an implicit
    /// default: whether first-run auto-provisioning is acceptable is an
    /// operator/deployment decision (regulated environments may require an
    /// out-of-band key ceremony instead), so the caller must opt in.
    pub auto_generate: bool,
}

/// PKCS#11 HSM-backed KEK (ADR 0016-v2 §2.5.1).
///
/// Wraps/unwraps the DEK via `CKM_AES_GCM` against a non-extractable
/// (`CKA_EXTRACTABLE=false`, `CKA_SENSITIVE=true`) AES-256 key object on the
/// token — the KEK never enters process memory (invariant 13).
pub struct Pkcs11Kek {
    // A PKCS#11 session is stateful (at most one active operation of a given
    // kind at a time) and `Session` is `Send` but not `Sync`; the mutex
    // serializes concurrent wrap/unwrap calls and makes the provider `Sync`
    // as required by `KekProvider`.
    session: Mutex<Session>,
    key: ObjectHandle,
}

impl Pkcs11Kek {
    /// Open a session against the configured token and resolve (or, if
    /// `auto_generate` is set, create) the AES KEK object.
    pub fn open(params: Pkcs11KekParams<'_>) -> Result<Self, CryptoError> {
        let pkcs11 = Pkcs11::new(params.module_path)
            .map_err(|e| CryptoError::Pkcs11(format!("loading PKCS#11 module: {e}")))?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| CryptoError::Pkcs11(format!("initializing PKCS#11 module: {e}")))?;

        let slot = resolve_slot(&pkcs11, &params.slot)?;
        let session = pkcs11
            .open_rw_session(slot)
            .map_err(|e| CryptoError::Pkcs11(format!("opening PKCS#11 session: {e}")))?;

        let pin_str = std::str::from_utf8(params.pin)
            .map_err(|_| CryptoError::Pkcs11("PKCS#11 PIN is not valid UTF-8".into()))?;
        session
            .login(UserType::User, Some(&AuthPin::new(pin_str.into())))
            .map_err(|e| CryptoError::Pkcs11(format!("PKCS#11 login failed: {e}")))?;

        let key = find_key(&session, params.key_label)?;
        let key = match key {
            Some(key) => key,
            None if params.auto_generate => generate_key(&session, params.key_label)?,
            None => {
                return Err(CryptoError::Pkcs11(format!(
                    "no AES key object with label {:?} on token and auto_generate is disabled",
                    params.key_label
                )));
            }
        };

        Ok(Self {
            session: Mutex::new(session),
            key,
        })
    }
}

fn resolve_slot(pkcs11: &Pkcs11, selector: &SlotSelector) -> Result<Slot, CryptoError> {
    match selector {
        SlotSelector::Id(id) => Slot::try_from(*id)
            .map_err(|e| CryptoError::Pkcs11(format!("invalid PKCS#11 slot id {id}: {e}"))),
        SlotSelector::Label(label) => {
            let slots = pkcs11
                .get_slots_with_token()
                .map_err(|e| CryptoError::Pkcs11(format!("listing PKCS#11 slots: {e}")))?;
            for slot in slots {
                let info = pkcs11
                    .get_token_info(slot)
                    .map_err(|e| CryptoError::Pkcs11(format!("reading token info: {e}")))?;
                if info.label() == label {
                    return Ok(slot);
                }
            }
            Err(CryptoError::Pkcs11(format!(
                "no PKCS#11 slot with token label {label:?}"
            )))
        }
    }
}

fn find_key(session: &Session, label: &str) -> Result<Option<ObjectHandle>, CryptoError> {
    let template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let mut found = session
        .find_objects(&template)
        .map_err(|e| CryptoError::Pkcs11(format!("finding PKCS#11 key object: {e}")))?;
    Ok(found.pop())
}

fn generate_key(session: &Session, label: &str) -> Result<ObjectHandle, CryptoError> {
    let template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::ValueLen(32.into()),
    ];
    session
        .generate_key(&Mechanism::AesKeyGen, &template)
        .map_err(|e| CryptoError::Pkcs11(format!("generating PKCS#11 AES key: {e}")))
}

impl KekProvider for Pkcs11Kek {
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        let mut nonce_bytes: [u8; 12] = rand::rng().random();
        let gcm_params = GcmParams::new(&mut nonce_bytes, DEK_WRAP_AD, 128.into())
            .map_err(|e| CryptoError::Pkcs11(format!("building GCM parameters: {e}")))?;

        let session = self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ciphertext_and_tag = session
            .encrypt(&Mechanism::AesGcm(gcm_params), self.key, dek)
            .map_err(|_| CryptoError::AesEncrypt)?;
        drop(session);

        // ciphertext_and_tag is [32-byte ciphertext][16-byte tag] per the
        // PKCS#11 CKM_AES_GCM convention (tag appended to the output).
        if ciphertext_and_tag.len() != 32 + 16 {
            return Err(CryptoError::AesEncrypt);
        }

        let mut out = Vec::with_capacity(12 + 32 + 16);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext_and_tag);
        Ok(out)
    }

    fn unwrap_dek(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        // Layout: [12-byte nonce][32-byte ciphertext][16-byte tag]
        if wrapped.len() != 12 + 32 + 16 {
            return Err(CryptoError::WrappedDekSize);
        }
        let mut nonce_bytes: [u8; 12] = wrapped[..12]
            .try_into()
            .map_err(|_| CryptoError::WrappedDekSize)?;
        let ciphertext_and_tag = &wrapped[12..];

        let gcm_params = GcmParams::new(&mut nonce_bytes, DEK_WRAP_AD, 128.into())
            .map_err(|e| CryptoError::Pkcs11(format!("building GCM parameters: {e}")))?;

        let session = self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let plaintext = Zeroizing::new(
            session
                .decrypt(&Mechanism::AesGcm(gcm_params), self.key, ciphertext_and_tag)
                .map_err(|_| CryptoError::AesDecrypt)?,
        );
        drop(session);

        if plaintext.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&plaintext);
        Ok(out)
    }
}
