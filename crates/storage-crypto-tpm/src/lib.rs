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
//! # TPM 2.0 KEK provider
//!
//! Implements [`TpmKek`], a [`KekProvider`] backed by two TPM-resident,
//! non-duplicable keys (ADR 0016-v2 §2.5.2): an AES-256-CFB key for
//! confidentiality and an HMAC-SHA256 key for integrity. TPM 2.0 has no
//! native AES-GCM command (`TPM2_EncryptDecrypt2` only supports
//! CFB/CBC/CTR/OFB/ECB), so this provider uses Encrypt-then-MAC instead,
//! checking the MAC (constant-time) before ever attempting decryption
//! (invariant 15).
//!
//! Wire format: `[16-byte iv][32-byte ciphertext][32-byte HMAC tag]` — 80
//! bytes for a 32-byte DEK. Distinct from [`EnvKek`]'s GCM format, but still
//! opaque `Vec<u8>` behind [`KekProvider`].
//!
//! Kept in its own crate for the same reason as `storage-crypto-pkcs11`: the
//! FFI-heavy `tss-esapi` dependency (and its `tpm2-tss` system library
//! requirement) stays out of the crate that owns the workspace's
//! `unsafe_code = "deny"` core primitives.
//!
//! ## Key provisioning
//!
//! Both TPM keys are children of a primary key that is *not* persisted: TPM
//! 2.0 primary key derivation is deterministic given the same hierarchy,
//! template and (empty) `unique` field, so recreating it on every [`open`]
//! reproduces the same parent without needing storage. It exists only to
//! load/create the two children and is flushed immediately afterwards.
//!
//! The AES and HMAC child keys themselves need durable identity across
//! process restarts, selected by [`KeyReference`]:
//!
//! * [`KeyReference::PersistentHandle`] — the AES key lives at the given
//!   persistent handle, the HMAC key at `handle + 1`. Both must already be
//!   provisioned (via [`Pkcs11Kek`]-style `auto_generate`, see below) unless
//!   `auto_generate` is set.
//! * [`KeyReference::ContextFile`] — the AES key's `(public, private)` blobs
//!   (TPM-encrypted under the primary, safe to store outside the TPM) are
//!   marshalled to the given path; the HMAC key's blobs go to `<path>.hmac`.
//!
//! [`EnvKek`]: openstack_keystone_storage_crypto::kek::EnvKek
//! [`open`]: TpmKek::open
//! [`Pkcs11Kek`]: ../openstack_keystone_storage_crypto_pkcs11/struct.Pkcs11Kek.html

use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

use openstack_keystone_storage_crypto::error::CryptoError;
use openstack_keystone_storage_crypto::kek::KekProvider;
use rand::RngExt;
use subtle::ConstantTimeEq;
use tss_esapi::Context;
use tss_esapi::abstraction::cipher::Cipher;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Auth, Digest, InitialValue, KeyedHashScheme, MaxBuffer, Private, Public, PublicBuilder,
    PublicKeyedHashParameters, RsaExponent, SymmetricCipherParameters,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::utils::create_restricted_decryption_rsa_public;
use zeroize::Zeroizing;

/// Associated data used for DEK wrapping, matching [`EnvKek`]'s binding
/// context.
///
/// [`EnvKek`]: openstack_keystone_storage_crypto::kek::EnvKek
const DEK_WRAP_AD: &[u8] = b"keystone-dek-wrap-v1";

/// Selects how the AES/HMAC child key pair is identified and persisted.
#[derive(Debug, Clone)]
pub enum KeyReference {
    /// AES key at this persistent TPM handle, HMAC key at `handle + 1`.
    PersistentHandle(u32),
    /// AES key blobs at this path, HMAC key blobs at `<path>.hmac`.
    ContextFile(PathBuf),
}

/// Parameters needed to open (and, if missing, provision) the TPM KEK.
pub struct TpmKekParams<'a> {
    /// TCTI connection string (e.g. `"device:/dev/tpmrm0"` or
    /// `"swtpm:host=127.0.0.1,port=2321"`).
    pub tcti: &'a str,
    /// How to locate/persist the AES and HMAC child keys.
    pub key_reference: KeyReference,
    /// Auth value applied to both child keys, as raw bytes. `None`/empty
    /// means no auth is required to use them.
    pub auth: Option<&'a [u8]>,
    /// If the referenced key(s) don't exist yet, generate them instead of
    /// failing. See [`Pkcs11KekParams::auto_generate`] for the same
    /// caller-opts-in rationale.
    ///
    /// [`Pkcs11KekParams::auto_generate`]: ../openstack_keystone_storage_crypto_pkcs11/struct.Pkcs11KekParams.html#structfield.auto_generate
    pub auto_generate: bool,
}

/// TPM 2.0-backed KEK (ADR 0016-v2 §2.5.2).
pub struct TpmKek {
    // `Context` is `Send` but its FFI session/handle state means concurrent
    // use from multiple threads is unsound; the mutex serializes wrap/unwrap
    // calls and makes the provider `Sync` as `KekProvider` requires.
    context: Mutex<Context>,
    aes_key: KeyHandle,
    hmac_key: KeyHandle,
}

impl TpmKek {
    /// Open a TPM context, resolve (or, if `auto_generate` is set, create)
    /// the AES and HMAC child keys, and apply `auth` to both.
    pub fn open(params: TpmKekParams<'_>) -> Result<Self, CryptoError> {
        let tcti = TctiNameConf::from_str(params.tcti)
            .map_err(|e| CryptoError::Tpm(format!("invalid TCTI {:?}: {e}", params.tcti)))?;
        let mut context = Context::new(tcti)
            .map_err(|e| CryptoError::Tpm(format!("opening TPM context: {e}")))?;

        let auth_value = match params.auth {
            Some(bytes) if !bytes.is_empty() => Some(
                Auth::try_from(bytes.to_vec())
                    .map_err(|e| CryptoError::Tpm(format!("invalid TPM auth value: {e}")))?,
            ),
            _ => None,
        };

        context
            .tr_set_auth(Hierarchy::Owner.into(), Auth::default())
            .map_err(|e| CryptoError::Tpm(format!("setting owner auth: {e}")))?;
        let primary = context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.create_primary(
                    Hierarchy::Owner,
                    create_restricted_decryption_rsa_public(
                        Cipher::aes_128_cfb()
                            .try_into()
                            .map_err(|e| CryptoError::Tpm(format!("primary cipher: {e}")))?,
                        RsaKeyBits::Rsa2048,
                        RsaExponent::default(),
                    )
                    .map_err(|e| CryptoError::Tpm(format!("building primary template: {e}")))?,
                    None,
                    None,
                    None,
                    None,
                )
                .map_err(|e| CryptoError::Tpm(format!("creating TPM primary key: {e}")))
            })?
            .key_handle;

        let (aes_key, hmac_key) = match &params.key_reference {
            KeyReference::PersistentHandle(handle) => (
                resolve_persistent(
                    &mut context,
                    primary,
                    *handle,
                    aes_key_public,
                    auth_value.clone(),
                    params.auto_generate,
                )?,
                resolve_persistent(
                    &mut context,
                    primary,
                    handle
                        .checked_add(1)
                        .ok_or_else(|| CryptoError::Tpm("TPM handle overflow".into()))?,
                    hmac_key_public,
                    auth_value.clone(),
                    params.auto_generate,
                )?,
            ),
            KeyReference::ContextFile(path) => (
                resolve_context_file(
                    &mut context,
                    primary,
                    path,
                    aes_key_public,
                    auth_value.clone(),
                    params.auto_generate,
                )?,
                resolve_context_file(
                    &mut context,
                    primary,
                    &hmac_sibling_path(path),
                    hmac_key_public,
                    auth_value.clone(),
                    params.auto_generate,
                )?,
            ),
        };

        context
            .execute_without_session(|ctx| ctx.flush_context(primary.into()))
            .map_err(|e| CryptoError::Tpm(format!("flushing TPM primary key: {e}")))?;

        if let Some(auth) = &auth_value {
            context
                .tr_set_auth(aes_key.into(), auth.clone())
                .map_err(|e| CryptoError::Tpm(format!("setting AES key auth: {e}")))?;
            context
                .tr_set_auth(hmac_key.into(), auth.clone())
                .map_err(|e| CryptoError::Tpm(format!("setting HMAC key auth: {e}")))?;
        }

        Ok(Self {
            context: Mutex::new(context),
            aes_key,
            hmac_key,
        })
    }
}

fn hmac_sibling_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".hmac");
    PathBuf::from(s)
}

fn aes_key_public() -> Result<Public, CryptoError> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(true)
        .build()
        .map_err(|e| CryptoError::Tpm(format!("building AES key attributes: {e}")))?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::SymCipher)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
            Cipher::aes_256_cfb()
                .try_into()
                .map_err(|e| CryptoError::Tpm(format!("AES key cipher: {e}")))?,
        ))
        .with_symmetric_cipher_unique_identifier(Default::default())
        .build()
        .map_err(|e| CryptoError::Tpm(format!("building AES key template: {e}")))
}

fn hmac_key_public() -> Result<Public, CryptoError> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()
        .map_err(|e| CryptoError::Tpm(format!("building HMAC key attributes: {e}")))?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
            KeyedHashScheme::HMAC_SHA_256,
        ))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(|e| CryptoError::Tpm(format!("building HMAC key template: {e}")))
}

/// Resolve a child key at a persistent handle, creating and evicting it
/// there if missing and `auto_generate` is set.
fn resolve_persistent(
    context: &mut Context,
    primary: KeyHandle,
    handle: u32,
    public_template: fn() -> Result<Public, CryptoError>,
    auth_value: Option<Auth>,
    auto_generate: bool,
) -> Result<KeyHandle, CryptoError> {
    let persistent_handle = PersistentTpmHandle::new(handle)
        .map_err(|e| CryptoError::Tpm(format!("invalid persistent handle {handle:#x}: {e}")))?;

    if let Ok(object_handle) = context.tr_from_tpm_public(TpmHandle::Persistent(persistent_handle))
    {
        return Ok(KeyHandle::from(object_handle));
    }

    if !auto_generate {
        return Err(CryptoError::Tpm(format!(
            "no TPM key at persistent handle {handle:#x} and auto_generate is disabled"
        )));
    }

    let transient = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create(
                primary,
                public_template()?,
                auth_value.clone(),
                None,
                None,
                None,
            )
            .map_err(|e| CryptoError::Tpm(format!("creating TPM key: {e}")))
        })
        .and_then(|created| {
            context
                .execute_with_session(Some(AuthSession::Password), |ctx| {
                    ctx.load(primary, created.out_private, created.out_public)
                })
                .map_err(|e| CryptoError::Tpm(format!("loading created TPM key: {e}")))
        })?;

    let evicted = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(
                Provision::Owner,
                transient.into(),
                Persistent::Persistent(persistent_handle),
            )
        })
        .map_err(|e| CryptoError::Tpm(format!("persisting TPM key at {handle:#x}: {e}")))?;

    Ok(KeyHandle::from(evicted))
}

/// Resolve a child key from a context file, creating and saving it there if
/// missing and `auto_generate` is set.
fn resolve_context_file(
    context: &mut Context,
    primary: KeyHandle,
    path: &Path,
    public_template: fn() -> Result<Public, CryptoError>,
    auth_value: Option<Auth>,
    auto_generate: bool,
) -> Result<KeyHandle, CryptoError> {
    if let Some((private, public)) = read_key_blob(path)? {
        return context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.load(primary, private, public)
            })
            .map_err(|e| CryptoError::Tpm(format!("loading TPM key from {path:?}: {e}")));
    }

    if !auto_generate {
        return Err(CryptoError::Tpm(format!(
            "no TPM key context file at {path:?} and auto_generate is disabled"
        )));
    }

    let created = context.execute_with_session(Some(AuthSession::Password), |ctx| {
        ctx.create(primary, public_template()?, auth_value, None, None, None)
            .map_err(|e| CryptoError::Tpm(format!("creating TPM key: {e}")))
    })?;

    write_key_blob(path, &created.out_private, &created.out_public)?;

    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.load(primary, created.out_private, created.out_public)
        })
        .map_err(|e| CryptoError::Tpm(format!("loading newly created TPM key: {e}")))
}

/// Context file format: `[4-byte LE public len][public][4-byte LE private
/// len][private]`, each half TPM-marshalled. Returns `None` if the file
/// doesn't exist.
fn read_key_blob(path: &Path) -> Result<Option<(Private, Public)>, CryptoError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(CryptoError::Tpm(format!(
                "reading TPM key context file {path:?}: {e}"
            )));
        }
    };
    let bad_format = || CryptoError::Tpm(format!("malformed TPM key context file {path:?}"));

    let public_len = bytes.first_chunk::<4>().ok_or_else(bad_format)?;
    let public_len = u32::from_le_bytes(*public_len) as usize;
    let rest = bytes.get(4..).ok_or_else(bad_format)?;
    let public_bytes = rest.get(..public_len).ok_or_else(bad_format)?;
    let rest = rest.get(public_len..).ok_or_else(bad_format)?;

    let private_len = rest.first_chunk::<4>().ok_or_else(bad_format)?;
    let private_len = u32::from_le_bytes(*private_len) as usize;
    let rest = rest.get(4..).ok_or_else(bad_format)?;
    let private_bytes = rest.get(..private_len).ok_or_else(bad_format)?;

    let public = Public::unmarshall(public_bytes)
        .map_err(|e| CryptoError::Tpm(format!("unmarshalling TPM public blob: {e}")))?;
    // `Private` is a plain length-prefixed buffer type (TPM2B_PRIVATE), not a
    // `Marshall`/`UnMarshall` structure — its byte representation is exactly
    // what `Private::try_from` / `.value()` produce.
    let private = Private::try_from(private_bytes.to_vec())
        .map_err(|e| CryptoError::Tpm(format!("decoding TPM private blob: {e}")))?;
    Ok(Some((private, public)))
}

fn write_key_blob(path: &Path, private: &Private, public: &Public) -> Result<(), CryptoError> {
    let public_bytes = public
        .marshall()
        .map_err(|e| CryptoError::Tpm(format!("marshalling TPM public blob: {e}")))?;
    let private_bytes = private.value();

    let mut out = Vec::with_capacity(8 + public_bytes.len() + private_bytes.len());
    out.extend_from_slice(&(public_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&public_bytes);
    out.extend_from_slice(&(private_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(private_bytes);

    std::fs::write(path, out)
        .map_err(|e| CryptoError::Tpm(format!("writing TPM key context file {path:?}: {e}")))
}

impl KekProvider for TpmKek {
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        let iv_bytes: [u8; 16] = rand::rng().random();
        let mut context = self
            .context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let iv = InitialValue::try_from(iv_bytes.to_vec()).map_err(|_| CryptoError::AesEncrypt)?;
        let data = MaxBuffer::try_from(dek.to_vec()).map_err(|_| CryptoError::AesEncrypt)?;

        let (ciphertext, _) = context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.encrypt_decrypt_2(self.aes_key, false, SymmetricMode::Cfb, data, iv)
            })
            .map_err(|_| CryptoError::AesEncrypt)?;
        let ciphertext: Vec<u8> = ciphertext.to_vec();
        if ciphertext.len() != 32 {
            return Err(CryptoError::AesEncrypt);
        }

        let tag = compute_tag(&mut context, self.hmac_key, &iv_bytes, &ciphertext)
            .map_err(|_| CryptoError::AesEncrypt)?;

        let mut out = Vec::with_capacity(16 + 32 + 32);
        out.extend_from_slice(&iv_bytes);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn unwrap_dek(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        // Layout: [16-byte iv][32-byte ciphertext][32-byte HMAC tag]
        if wrapped.len() != 16 + 32 + 32 {
            return Err(CryptoError::WrappedDekSize);
        }
        let iv_bytes: [u8; 16] = wrapped[..16]
            .try_into()
            .map_err(|_| CryptoError::WrappedDekSize)?;
        let ciphertext = &wrapped[16..48];
        let expected_tag = &wrapped[48..];

        let mut context = self
            .context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Authenticate before decrypting (ADR invariant 15): compute and
        // constant-time-compare the tag before ever calling
        // encrypt_decrypt_2 on unauthenticated ciphertext.
        let actual_tag = compute_tag(&mut context, self.hmac_key, &iv_bytes, ciphertext)
            .map_err(|_| CryptoError::AesDecrypt)?;
        if actual_tag.ct_eq(expected_tag).unwrap_u8() != 1 {
            return Err(CryptoError::AesDecrypt);
        }

        let iv = InitialValue::try_from(iv_bytes.to_vec()).map_err(|_| CryptoError::AesDecrypt)?;
        let data = MaxBuffer::try_from(ciphertext.to_vec()).map_err(|_| CryptoError::AesDecrypt)?;
        let (plaintext, _) = context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.encrypt_decrypt_2(self.aes_key, true, SymmetricMode::Cfb, data, iv)
            })
            .map_err(|_| CryptoError::AesDecrypt)?;
        drop(context);

        // `plaintext` (a `MaxBuffer`) already wraps a `Zeroizing<Vec<u8>>`
        // internally — copy straight out of it via `.value()` rather than
        // `.to_vec()`-ing into a throwaway plain `Vec<u8>` that would hold
        // the unwrapped DEK without being zeroized on drop.
        if plaintext.value().len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(plaintext.value());
        Ok(out)
    }
}

/// `TPM2_HMAC(hmac_key, iv ++ ciphertext ++ DEK_WRAP_AD)`.
fn compute_tag(
    context: &mut Context,
    hmac_key: KeyHandle,
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut buf = Vec::with_capacity(iv.len() + ciphertext.len() + DEK_WRAP_AD.len());
    buf.extend_from_slice(iv);
    buf.extend_from_slice(ciphertext);
    buf.extend_from_slice(DEK_WRAP_AD);
    let buffer = MaxBuffer::try_from(buf).map_err(|e| CryptoError::Tpm(format!("{e}")))?;

    let digest = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.hmac(
                ObjectHandle::from(hmac_key),
                buffer,
                HashingAlgorithm::Sha256,
            )
        })
        .map_err(|e| CryptoError::Tpm(format!("computing HMAC tag: {e}")))?;
    Ok(digest.to_vec())
}
