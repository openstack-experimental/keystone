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
//! # Fernet token driver for the `openstack_keystone` crate

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fmt;
use std::io::{Cursor, Write};
use std::sync::Arc;

use base64::Engine;
use byteorder::ReadBytesExt;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use itertools::Itertools;
use openstack_keystone_key_repository::{CachedKeyRepository, FilesystemKeySource, LoadedKeys};
use rmp::{
    Marker,
    decode::{ValueReadError, read_marker, read_u8},
    encode::{write_array_len, write_pfix},
};
use tracing::{trace, warn};
use validator::Validate;

use openstack_keystone_config::Config;
use openstack_keystone_core::token::{TokenProviderError, backend::TokenBackend};
use openstack_keystone_core_types::token::*;
//    application_credential::ApplicationCredentialPayload,
// domain_scoped::DomainScopePayload,
//    federation_domain_scoped::FederationDomainScopePayload,
//    federation_project_scoped::FederationProjectScopePayload,
//    federation_unscoped::FederationUnscopedPayload,
// project_scoped::ProjectScopePayload,    restricted::RestrictedPayload,
// trust::TrustPayload, unscoped::UnscopedPayload, *,
//};
use utils::FernetUtils;

mod application_credential;
mod domain_scoped;
mod error;
mod federation_domain_scoped;
mod federation_project_scoped;
mod federation_unscoped;
mod project_scoped;
mod restricted;
mod system_scoped;
mod trust;
mod unscoped;
pub mod utils;

pub use error::FernetDriverError;

/// Fernet token provider.
pub struct FernetTokenProvider {
    config: Config,
    utils: FernetUtils,
    /// Populated by [`Self::load_keys`]: an always-fresh, auto-refreshing
    /// view of the key repository. `None` until then — `encrypt`/`decrypt`
    /// error rather than silently reading the filesystem on every call.
    cached: Option<CachedKeyRepository<FilesystemKeySource>>,
    /// Map of the configured authentication methods.
    auth_map: BTreeMap<u8, String>,
    /// Cached permutations of auth_methods to the payload code.
    auth_methods_code_cache: BTreeMap<u8, HashSet<String>>,
}

pub trait MsgPackToken {
    type Token;

    /// Construct MsgPack payload for the Token.
    ///
    /// # Parameters
    /// - `_wd`: The writer to write the payload to.
    /// - `_fernet_provider`: The Fernet token provider.
    ///
    /// # Returns
    /// A `Result` indicating success or a `FernetDriverError`.
    fn assemble<W: Write>(
        &self,
        _wd: &mut W,
        _fernet_provider: &FernetTokenProvider,
    ) -> Result<(), FernetDriverError> {
        Ok(())
    }

    /// Parse MsgPack payload into the Token.
    ///
    /// # Parameters
    /// - `rd`: The reader to read the payload from.
    /// - `fernet_provider`: The Fernet token provider.
    ///
    /// # Returns
    /// A `Result` containing the `Token` if successful, or a
    /// `FernetDriverError`.
    fn disassemble(
        rd: &mut &[u8],
        fernet_provider: &FernetTokenProvider,
    ) -> Result<Self::Token, FernetDriverError>;
}

impl fmt::Debug for FernetTokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FernetTokenProvider").finish()
    }
}

/// Read the payload version.
///
/// # Parameters
/// - `rd`: The reader to read the payload version from.
///
/// # Returns
/// A `Result` containing the payload version if successful, or a
/// `FernetDriverError`.
fn read_payload_token_type(rd: &mut &[u8]) -> Result<u8, FernetDriverError> {
    match read_marker(rd).map_err(ValueReadError::from)? {
        Marker::FixPos(dt) => Ok(dt),
        Marker::U8 => Ok(read_u8(rd)?),
        _ => Err(FernetDriverError::InvalidToken),
    }
}

/// Calculate possible combinations of the vector string elements.
///
/// # Parameters
/// - `iter`: An iterator over string elements.
///
/// # Returns
/// An iterator over hash sets of string combinations.
fn all_combinations<I>(iter: I) -> impl IntoIterator<Item = HashSet<String>>
where
    I: IntoIterator<Item = String>,
{
    let items: Vec<String> = iter.into_iter().collect();
    let n = items.len();
    let mut result = Vec::new();

    // There are 2^n possible subsets
    for mask in 0..(1 << n) {
        let mut subset = HashSet::new();
        for (i, am) in items.iter().enumerate() {
            if (mask & (1 << i)) != 0 {
                subset.insert(am.clone());
            }
        }
        result.push(subset);
    }
    result.into_iter().filter(|v| !v.is_empty())
}

impl FernetTokenProvider {
    /// Construct new FernetTokenProvider.
    ///
    /// # Parameters
    /// - `config`: The configuration for the provider.
    ///
    /// # Returns
    /// A new `FernetTokenProvider` instance.
    pub fn new(config: Config) -> Self {
        let mut slf = Self {
            utils: FernetUtils {
                key_repository: config.fernet_tokens.key_repository.clone(),
                max_active_keys: config.fernet_tokens.max_active_keys,
            },
            config,
            cached: None,
            auth_map: BTreeMap::new(),
            auth_methods_code_cache: BTreeMap::new(),
        };
        slf.reload_config();
        slf
    }

    /// Reload the provider configuration.
    pub fn reload_config(&mut self) {
        let methods = &self.config.auth.methods;
        // The auth methods used by a token are encoded as a single `u8`
        // bitmask (one bit per configured method), so at most 8 methods can
        // be represented. `1u8 << k` would overflow (panic in debug, wrap
        // and collide bits in release) for any method beyond the 8th.
        if methods.len() > 8 {
            warn!(
                configured = methods.len(),
                usable = ?&methods[..8],
                dropped = ?&methods[8..],
                "more than 8 authentication methods are configured; only the \
                 first 8 can be encoded into a Fernet token, the rest will be \
                 rejected when used for authentication"
            );
        }
        self.auth_map = BTreeMap::from_iter(
            methods
                .iter()
                .take(8)
                .enumerate()
                .map(|(k, v)| (1u8 << k, v.clone())),
        );
        self.set_auth_methods_cache_combinations();
    }

    /// Set the cache for authentication method combinations.
    fn set_auth_methods_cache_combinations(&mut self) {
        self.auth_methods_code_cache.clear();
        for auth_pairs in all_combinations(self.auth_map.values().cloned()) {
            let pair: HashSet<String> = HashSet::from_iter(auth_pairs);
            self.encode_auth_methods(pair.clone())
                .ok()
                .map(|val| self.auth_methods_code_cache.insert(val, pair));
        }
    }

    /// Encode the list of auth_methods into a single integer.
    ///
    /// # Parameters
    /// - `methods`: An iterator over the authentication methods.
    ///
    /// # Returns
    /// A `Result` containing the encoded integer if successful, or a
    /// `FernetDriverError`.
    #[tracing::instrument(level = "trace", skip(self, methods))]
    pub(crate) fn encode_auth_methods<I>(&self, methods: I) -> Result<u8, FernetDriverError>
    where
        I: IntoIterator<Item = String>,
    {
        let me: HashSet<String> = HashSet::from_iter(methods.into_iter());
        let unsupported_methods: Vec<&String> = me
            .iter()
            .filter(|method| !self.auth_map.values().any(|known| known == *method))
            .sorted()
            .collect();
        if me.is_empty() || !unsupported_methods.is_empty() {
            return Err(FernetDriverError::UnsupportedAuthMethods(
                unsupported_methods.iter().join(","),
            ));
        }

        let res = self
            .auth_map
            .iter()
            .fold(0, |acc, (k, v)| acc + if me.contains(v) { *k } else { 0 });
        Ok(res)
    }

    /// Decode the integer into the list of auth_methods.
    ///
    /// # Parameters
    /// - `value`: The encoded authentication methods integer.
    ///
    /// # Returns
    /// A `Result` containing a vector of authentication methods if successful,
    /// or a `FernetDriverError`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub(crate) fn decode_auth_methods(&self, value: u8) -> Result<Vec<String>, FernetDriverError> {
        if let Some(res) = self.auth_methods_code_cache.get(&value) {
            Ok(res.iter().cloned().collect())
        } else {
            trace!("Auth methods cache miss.");
            let mut results: Vec<String> = Vec::new();
            let mut auth: u8 = value;
            // Bits must be tested from the largest to the smallest: after
            // subtracting a matched bit, the remaining `auth` value is only
            // guaranteed to be smaller than the next (smaller) bit being
            // tested. Iterating in ascending order instead would test
            // `auth / idx == 1` while a larger, not-yet-subtracted bit is
            // still contributing to `auth`, causing that division to skip
            // right past 1 and silently drop the smaller method.
            for (idx, name) in self.auth_map.iter().rev() {
                // (lbragstad): By dividing the method_int by each key in the
                // method_map, we know if the division results in an integer of 1, that
                // key was used in the construction of the total sum of the method_int.
                // In that case, we should confirm the key value and store it so we can
                // look it up later. Then we should take the remainder of what is
                // confirmed and the method_int and continue the process. In the end, we
                // should have a list of integers that correspond to indexes in our
                // method_map and we can reinflate the methods that the original
                // method_int represents.
                let result: u8 = auth / idx;
                if result == 1 {
                    results.push(name.clone());
                    auth -= idx;
                }
            }
            Ok(results)
        }
    }

    /// Parse binary blob as MessagePack after encrypting it with Fernet.
    ///
    /// # Parameters
    /// - `rd`: The reader to read the payload from.
    /// - `timestamp`: The creation timestamp of the payload.
    ///
    /// # Returns
    /// A `Result` containing the decrypted `Token` if successful, or a
    /// `FernetDriverError`.
    fn decode(
        &self,
        rd: &mut &[u8],
        timestamp: DateTime<Utc>,
    ) -> Result<FernetToken, FernetDriverError> {
        if let Marker::FixArray(_) = read_marker(rd).map_err(ValueReadError::from)? {
            let mut token: FernetToken = match read_payload_token_type(rd)? {
                0 => Ok(UnscopedPayload::disassemble(rd, self)?.into()),
                1 => Ok(DomainScopePayload::disassemble(rd, self)?.into()),
                2 => Ok(ProjectScopePayload::disassemble(rd, self)?.into()),
                3 => Ok(TrustPayload::disassemble(rd, self)?.into()),
                4 => Ok(FederationUnscopedPayload::disassemble(rd, self)?.into()),
                5 => Ok(FederationProjectScopePayload::disassemble(rd, self)?.into()),
                6 => Ok(FederationDomainScopePayload::disassemble(rd, self)?.into()),
                8 => Ok(SystemScopePayload::disassemble(rd, self)?.into()),
                9 => Ok(ApplicationCredentialPayload::disassemble(rd, self)?.into()),
                11 => Ok(RestrictedPayload::disassemble(rd, self)?.into()),
                other => Err(FernetDriverError::InvalidTokenType(other)),
            }?;
            token.set_issued_at(timestamp);
            Ok(token.to_owned())
        } else {
            Err(FernetDriverError::InvalidToken)
        }
    }

    /// Encode Token as binary blob as MessagePack.
    ///
    /// # Parameters
    /// - `token`: The token to encode.
    ///
    /// # Returns
    /// A `Result` containing the encoded bytes if successful, or a
    /// `FernetDriverError`.
    fn encode(&self, token: &FernetToken) -> Result<Bytes, FernetDriverError> {
        token.validate()?;
        let mut buf = vec![];
        match token {
            FernetToken::ApplicationCredential(data) => {
                write_array_len(&mut buf, 7)
                    .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 9).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            FernetToken::DomainScope(data) => {
                write_array_len(&mut buf, 6)
                    .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 1).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            FernetToken::Trust(data) => {
                write_array_len(&mut buf, 7)
                    .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 3).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            FernetToken::FederationUnscoped(data) => {
                write_array_len(&mut buf, 8)
                    .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 4).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            FernetToken::FederationProjectScope(data) => {
                write_array_len(&mut buf, 9)
                    .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 5).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            FernetToken::FederationDomainScope(data) => {
                write_array_len(&mut buf, 9)
                    .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 6).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            FernetToken::ProjectScope(data) => {
                write_array_len(&mut buf, 6)
                    .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 2).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            FernetToken::Restricted(data) => {
                write_array_len(&mut buf, 9)
                    .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 11)
                    .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            FernetToken::SystemScope(data) => {
                write_array_len(&mut buf, 6)
                    .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 8).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            FernetToken::Unscoped(data) => {
                write_array_len(&mut buf, 5)
                    .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 0).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
        }
        Ok(buf.into())
    }

    /// The current key snapshot, kept fresh in the background once
    /// [`Self::load_keys`] has started it.
    ///
    /// # Errors
    /// [`FernetDriverError::FernetKeysMissing`] if [`Self::load_keys`] has
    /// not been called yet.
    fn current_keys(&self) -> Result<Arc<LoadedKeys>, FernetDriverError> {
        self.cached
            .as_ref()
            .map(CachedKeyRepository::current)
            .ok_or(FernetDriverError::FernetKeysMissing)
    }

    /// Load fernet keys from FS and start watching for changes: this is a
    /// one-time initialization (call once before serving traffic) that
    /// keeps `decrypt`/`encrypt` on a cheap, always-current cached snapshot
    /// rather than reading the filesystem on every call, and picks up a
    /// rotation without a service restart (ADR 0019 §4, shared with the
    /// credential key repository).
    ///
    /// # Returns
    /// A `Result` indicating success or a `FernetDriverError`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub async fn load_keys(&mut self) -> Result<(), FernetDriverError> {
        self.cached = Some(
            self.utils
                .start_cached(self.config.fernet_tokens.insecure_allow_null_key)
                .await?,
        );
        Ok(())
    }

    /// Decrypt the token.
    ///
    /// 1. Decrypt as Fernet.
    /// 2. Unpack MessagePack payload.
    ///
    /// # Parameters
    /// - `credential`: The encrypted token credential.
    ///
    /// # Returns
    /// A `Result` containing the decrypted `Token` if successful, or a
    /// `FernetDriverError`.
    pub fn decrypt(&self, credential: &str) -> Result<FernetToken, FernetDriverError> {
        let keys = self.current_keys()?;
        let payload = keys.multi_fernet.decrypt(credential)?;

        self.decode(&mut payload.as_slice(), get_fernet_timestamp(credential)?)
    }

    /// Encrypt the token.
    ///
    /// # Parameters
    /// - `token`: The token to encrypt.
    ///
    /// # Returns
    /// A `Result` containing the encrypted token string if successful, or a
    /// `FernetDriverError`.
    pub fn encrypt(&self, token: &FernetToken) -> Result<String, FernetDriverError> {
        let payload = self.encode(token)?;
        let keys = self.current_keys()?;
        Ok(keys.multi_fernet.encrypt(&payload))
    }
}

impl TokenBackend for FernetTokenProvider {
    /// Set configuration.
    ///
    /// # Parameters
    /// - `config`: The new configuration.
    fn set_config(&mut self, config: Config) {
        self.config = config;
        self.reload_config();
    }

    /// Decrypt the token.
    ///
    /// # Parameters
    /// - `credential`: The encrypted token credential.
    ///
    /// # Returns
    /// A `Result` containing the decrypted `Token` if successful, or a
    /// `TokenProviderError`.
    #[tracing::instrument(level = "trace", skip(self, credential))]
    fn decode(&self, credential: &str) -> Result<FernetToken, TokenProviderError> {
        Ok(self.decrypt(credential)?)
    }

    /// Encrypt the token.
    ///
    /// # Parameters
    /// - `token`: The token to encrypt.
    ///
    /// # Returns
    /// A `Result` containing the encrypted token string if successful, or a
    /// `TokenProviderError`.
    #[tracing::instrument(level = "trace", skip(self, token))]
    fn encode(&self, token: &FernetToken) -> Result<String, TokenProviderError> {
        Ok(self.encrypt(token)?)
    }
}

/// Decode the fernet payload as Base64_urlsafe.
///
/// # Parameters
/// - `input`: The Base64 encoded input string.
///
/// # Returns
/// A `Result` containing the decoded bytes if successful, or a
/// `base64::DecodeError`.
fn b64_decode_url(input: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input.trim_end_matches('='))
}

/// Get the fernet payload creation timestamp.
///
/// Extract the payload creation timestamp in the UTC.
///
/// # Parameters
/// - `payload`: The fernet token payload.
///
/// # Returns
/// A `Result` containing the `DateTime<Utc>` if successful, or a
/// `FernetDriverError`.
fn get_fernet_timestamp(payload: &str) -> Result<DateTime<Utc>, FernetDriverError> {
    let data = b64_decode_url(payload)
        .map_err(|_| FernetDriverError::FernetDecryption(fernet::DecryptionError))?;

    let mut input = Cursor::new(data);

    match input.read_u8() {
        Ok(0x80) => {}
        _ => return Err(FernetDriverError::FernetDecryption(fernet::DecryptionError)),
    }

    input
        .read_u64::<byteorder::BigEndian>()
        .map_err(|_| FernetDriverError::FernetDecryption(fernet::DecryptionError))
        .and_then(|val| {
            TryInto::try_into(val).map_err(|err| FernetDriverError::TokenTimestampOverflow {
                value: val,
                source: err,
            })
        })
        .and_then(|val| {
            DateTime::from_timestamp_secs(val)
                .ok_or_else(|| FernetDriverError::FernetDecryption(fernet::DecryptionError))
        })
}

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

#[cfg(feature = "bench_internals")]
/// Conditionally expose the function when the 'bench_internals' feature is
/// enabled.
///
/// # Parameters
/// - `payload`: The fernet token payload.
///
/// # Returns
/// A `Result` containing the `DateTime<Utc>` if successful, or a
/// `FernetDriverError`.
pub fn bench_get_fernet_timestamp(payload: &str) -> Result<DateTime<Utc>, FernetDriverError> {
    get_fernet_timestamp(payload)
}

#[cfg(test)]
pub mod tests {
    use std::fs::File;
    use std::io::Write;

    use chrono::{Local, SubsecRound};
    //use config;
    use tempfile::tempdir;
    use uuid::Uuid;

    use openstack_keystone_config::Config;

    use super::*;

    pub(crate) fn setup_config() -> Config {
        let keys_dir = tempdir().unwrap();
        // write fernet key used to generate tokens in python
        let file_path = keys_dir.path().join("0");
        let mut tmp_file = File::create(file_path).unwrap();
        write!(tmp_file, "BFTs1CIVIBLTP4GOrQ26VETrJ7Zwz1O4wbEcCQ966eM=").unwrap();

        let builder = config::Config::builder()
            .set_override(
                "auth.methods",
                "password,token,openid,application_credential",
            )
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let mut config: Config = Config::try_from(builder).expect("can build a valid config");
        config.fernet_tokens.key_repository = keys_dir.keep();
        config
    }

    fn discard_issued_at(mut token: FernetToken) -> FernetToken {
        token.set_issued_at(Default::default());
        token
    }

    #[test]
    fn test_encode_auth_methods_rejects_unsupported_method() {
        let provider = FernetTokenProvider::new(setup_config());

        let result = provider.encode_auth_methods(["ec2credential".to_string()]);

        assert!(matches!(
            result,
            Err(FernetDriverError::UnsupportedAuthMethods(methods))
                if methods == "ec2credential"
        ));
    }

    #[test]
    fn test_encode_auth_methods_rejects_mixed_supported_and_unsupported_methods() {
        let provider = FernetTokenProvider::new(setup_config());

        let result =
            provider.encode_auth_methods(["token".to_string(), "ec2credential".to_string()]);

        assert!(matches!(
            result,
            Err(FernetDriverError::UnsupportedAuthMethods(methods))
                if methods == "ec2credential"
        ));
    }

    #[tokio::test]
    async fn test_decrypt_unscoped() {
        let token = "gAAAAABnt12vpnYCuUxl1lWQfTxwkBcZcgdK5wYons4BFHxxZLk326To5afinp29in7f5ZHR5K61Pl2voIjfbPKlL51KempshD4shfSje4RutbeXq-NT498eEcorzige5XBYGaoWuDTOKEDH2eXCMHhw9722j9iPP3Z4r_1Zlmcqq1n2tndmvsA";

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        if let FernetToken::Unscoped(decrypted) = provider.decrypt(token).unwrap() {
            assert_eq!(decrypted.user_id, "4b7d364ad87d400bbd91798e3c15e9c2");
            let mut methods_curr = decrypted.methods.clone();
            methods_curr.sort();
            assert_eq!(methods_curr, ["password", "token"]);
            assert_eq!(
                decrypted.expires_at.to_rfc3339(),
                "2025-02-20T17:40:13+00:00"
            );
            assert_eq!(
                decrypted.audit_ids,
                vec!["sfROvzgjTdmbo8xZdcze-g", "FL7FbzBKQsK115_4TyyiIw"]
            );
        } else {
            panic!()
        }
    }

    #[tokio::test]
    async fn test_unscoped_roundtrip() {
        let token = FernetToken::Unscoped(UnscopedPayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_domain() {
        let token = "gAAAAABnt16C_ve4dDc7TeU857pwTXGJfGqNA4uJ308_2o_F9T_8WenNBatll0Q36wGz79dSI6RQnuN2PbK17wxQbn9jXscDh2ie3ZrW-WL5gG3gWK6FiPleAiU3kJN5mkskViJOIN-ZpP2B15fmZiYijelQ9TQuhQ";

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        if let FernetToken::DomainScope(decrypted) = provider.decrypt(token).unwrap() {
            assert_eq!(decrypted.user_id, "4b7d364ad87d400bbd91798e3c15e9c2");
            assert_eq!(decrypted.domain_id, "default");
            assert_eq!(decrypted.methods, vec!["password"]);
            assert_eq!(
                decrypted.expires_at.to_rfc3339(),
                "2025-02-20T17:55:30+00:00"
            );
            assert_eq!(decrypted.audit_ids, vec!["eikbCiM0SsO5P9d_GbVhBQ"]);
        } else {
            panic!()
        }
    }

    #[tokio::test]
    async fn test_domain_roundtrip() {
        let token = FernetToken::DomainScope(DomainScopePayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            domain_id: Uuid::new_v4().simple().to_string(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_project() {
        let token = "gAAAAABns2ixy75K_KfoosWLrNNqG6KW8nm3Xzv0_2dOx8ODWH7B8i2g8CncGLO6XBEH_TYLg83P6XoKQ5bU8An8Kqgw9WX3bvmEQXphnwPM6aRAOQUSdVhTlUm_8otDG9BS2rc70Q7pfy57S3_yBgimy-174aKdP8LPusvdHZsQPEJO9pfeXWw";

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        if let FernetToken::ProjectScope(decrypted) = provider.decrypt(token).unwrap() {
            assert_eq!(decrypted.user_id, "4b7d364ad87d400bbd91798e3c15e9c2");
            assert_eq!(decrypted.project_id, "97cd761d581b485792a4afc8cc6a998d");
            assert_eq!(decrypted.methods, vec!["password"]);
            assert_eq!(
                decrypted.expires_at.to_rfc3339(),
                "2025-02-17T17:49:53+00:00"
            );
            assert_eq!(decrypted.audit_ids, vec!["fhRNUHHPTkitISpEYkY_mQ"]);
        } else {
            panic!()
        }
    }

    #[tokio::test]
    async fn test_project_roundtrip() {
        let token = FernetToken::ProjectScope(ProjectScopePayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            project_id: Uuid::new_v4().simple().to_string(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_federation_unscoped() {
        let token = "gAAAAABoMdfwBgwjAfYCp3RisL_XKSdGKmBqg7ia8jkfsKIXnap_bQ5gUTZGwgEERlpFKzbwpkV-cpiFDuhe9RAnCtbQxEhP7Rg1vt1VLm8afGTulDaLclqot2NC-BONFO2k3V3KyIa-Xrq0mCEGOk-BhNZy2C6iwrWanPCjCuZrWCq4FBirtMs2vrnZPWG5FTGqqkvdQvGj";

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        if let FernetToken::FederationUnscoped(decrypted) = provider.decrypt(token).unwrap() {
            assert_eq!(decrypted.user_id, "8980e124df5245509131bdc5c66c54cc");
            assert_eq!(decrypted.methods, vec!["openid"]);
            assert_eq!(
                decrypted.expires_at.to_rfc3339(),
                "2025-05-24T16:30:03+00:00"
            );
            assert_eq!(
                decrypted.audit_ids,
                vec!["3622030ded92477095dadcde340770e5"]
            );
            assert_eq!(decrypted.idp_id, "idp_id");
            assert_eq!(decrypted.protocol_id, "oidc");
            assert_eq!(decrypted.group_ids, vec!["g1", "g2"]);
        } else {
            panic!()
        }
    }

    #[tokio::test]
    async fn test_federation_unscoped_roundtrip() {
        let token = FernetToken::FederationUnscoped(FederationUnscopedPayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            group_ids: vec!["g1".into()],
            idp_id: "idp_id".into(),
            protocol_id: "proto".into(),

            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_federation_project_scope() {
        let token = "gAAAAABoNdYE5zCP0qQtHqhdbZHQ7YdLvfDlUTpLou8FJFoMKsd4I9jyVyaWrluYXKXofnwzemA-wybhtbNruwqDYH-wmHdMlgYuZyy21o8ylphU5yd2b-5KvGpXo61fTVTzhdHFTzJKVit_7Lcwq0S45xQ9x14sVRd870NEwfmOvUVR5BGzmnpFLvWtkaPSpbxMAzfn_NSC";

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        if let FernetToken::FederationProjectScope(decrypted) = provider.decrypt(token).unwrap() {
            assert_eq!(decrypted.user_id, "8980e124df5245509131bdc5c66c54cc");
            assert_eq!(decrypted.methods, vec!["openid"]);
            assert_eq!(
                decrypted.expires_at.to_rfc3339(),
                "2025-05-27T17:11:00+00:00",
            );
            assert_eq!(
                decrypted.audit_ids,
                vec!["dcbf4d403b7a45dca32d029d54c953d9"]
            );
            assert_eq!(decrypted.project_id, "pid");
            assert_eq!(decrypted.idp_id, "idp_id");
            assert_eq!(decrypted.protocol_id, "oidc");
            assert_eq!(decrypted.group_ids, vec!["g1", "g2"]);
        } else {
            panic!()
        }
    }

    #[tokio::test]
    async fn test_federation_project_scope_roundtrip() {
        let token = FernetToken::FederationProjectScope(FederationProjectScopePayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            project_id: "pid".into(),
            group_ids: vec!["g1".into()],
            idp_id: "idp_id".into(),
            protocol_id: "proto".into(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_federation_domain_scope() {
        let token = "gAAAAABoNddwFaB2Oq26-4f8nRK3Bph7-QsIh30Rbefbb78owJXaQcjNQm5Qq1gHouS6JSqgfpdna3ML1vdTVnVnFScX-T-CZ-CqtBPUuEBHFEzdNBDKQHloYajZ2sknwbe_uIs1SDS9tBFLvkVth1eVjDhdEawINHjUCFhNPObZKas5V0j7bsvChNeZBKsznruJwCtcrWr5";

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        if let FernetToken::FederationDomainScope(decrypted) = provider.decrypt(token).unwrap() {
            assert_eq!(decrypted.user_id, "8980e124df5245509131bdc5c66c54cc");
            assert_eq!(decrypted.methods, vec!["openid"]);
            assert_eq!(
                decrypted.expires_at.to_rfc3339(),
                "2025-05-27T17:17:04+00:00",
            );
            assert_eq!(
                decrypted.audit_ids,
                vec!["ab892135f51240f5bae8ec7179873bf6"]
            );
            assert_eq!(decrypted.domain_id, "did");
            assert_eq!(decrypted.idp_id, "idp_id");
            assert_eq!(decrypted.protocol_id, "oidc");
            assert_eq!(decrypted.group_ids, vec!["g1", "g2"]);
        } else {
            panic!()
        }
    }

    #[tokio::test]
    async fn test_federation_domain_scope_roundtrip() {
        let token = FernetToken::FederationDomainScope(FederationDomainScopePayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            domain_id: "pid".into(),
            group_ids: vec!["g1".into()],
            idp_id: "idp_id".into(),
            protocol_id: "proto".into(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let config = setup_config();
        let mut provider = FernetTokenProvider::new(config);
        provider.load_keys().await.unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_application_credential() {
        let token = "gAAAAABnt11m57ZlI9JU0g2BKJw2EN-InbAIijcIG7SxvPATntgTlcTMwha-Fh7isNNIwDq2WaWglV1nYgftfoUK245ZnEJ0_gXaIhl6COhNommYv2Bs9PnJqfgrrxrIrB8rh4pfeyCtMkv5ePYgFFPyRFE37l3k7qL5p7qVhYT37yT1-K5lYAV0f6Vy70h3KX1HO0m6Rl90";

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        if let FernetToken::ApplicationCredential(decrypted) = provider.decrypt(token).unwrap() {
            assert_eq!(decrypted.user_id, "4b7d364ad87d400bbd91798e3c15e9c2");
            assert_eq!(decrypted.project_id, "97cd761d581b485792a4afc8cc6a998d");
            assert_eq!(decrypted.methods, vec!["application_credential"]);
            assert_eq!(
                decrypted.expires_at.to_rfc3339(),
                "2025-02-20T17:50:46+00:00"
            );
            assert_eq!(decrypted.audit_ids, vec!["kD7Cwc8fSZuWNPZhy0fLVg"]);
            assert_eq!(
                decrypted.application_credential_id,
                "a67630c36e1b48839091c905177c5598"
            );
        } else {
            panic!()
        }
    }

    #[tokio::test]
    async fn test_application_credential_roundtrip() {
        let token = FernetToken::ApplicationCredential(ApplicationCredentialPayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["application_credential".into()],
            project_id: Uuid::new_v4().simple().to_string(),
            application_credential_id: Uuid::new_v4().simple().to_string(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_restricted_roundtrip() {
        let token = FernetToken::Restricted(RestrictedPayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            token_restriction_id: Uuid::new_v4().simple().to_string(),
            project_id: Uuid::new_v4().simple().to_string(),
            allow_renew: true,
            allow_rescope: true,
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_trust_roundtrip() {
        let token = FernetToken::Trust(TrustPayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            trust_id: Uuid::new_v4().simple().to_string(),
            project_id: Uuid::new_v4().simple().to_string(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().await.unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[test]
    fn test_decode_auth_methods_cache_miss_preserves_all_bits() {
        // setup_config() configures "password,token,openid,application_credential",
        // so bits are password=1, token=2, openid=4, application_credential=8.
        let mut provider = FernetTokenProvider::new(setup_config());
        // Force the fallback bit-decomposition path (normally only hit when a
        // token's bitmask isn't one of the pre-cached combinations).
        provider.auth_methods_code_cache.clear();

        let mut methods = provider.decode_auth_methods(0b0101).unwrap(); // password + openid
        methods.sort();
        assert_eq!(methods, vec!["openid", "password"]);
    }

    #[test]
    fn test_reload_config_caps_more_than_8_auth_methods() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "m1,m2,m3,m4,m5,m6,m7,m8,m9")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let config: Config = Config::try_from(builder).expect("can build a valid config");

        // Must not panic (shift overflow) despite 9 configured methods.
        let provider = FernetTokenProvider::new(config);
        assert_eq!(provider.auth_map.len(), 8);
        assert!(!provider.auth_map.values().any(|v| v == "m9"));
    }

    #[tokio::test]
    async fn test_eighth_auth_method_roundtrip() {
        // The 8th configured method encodes to bit 128, which the MessagePack
        // positive-fixint format used for the methods byte cannot represent.
        let keys_dir = tempdir().unwrap();
        let file_path = keys_dir.path().join("0");
        let mut tmp_file = File::create(file_path).unwrap();
        write!(tmp_file, "BFTs1CIVIBLTP4GOrQ26VETrJ7Zwz1O4wbEcCQ966eM=").unwrap();

        let builder = config::Config::builder()
            .set_override("auth.methods", "m1,m2,m3,m4,m5,m6,m7,m8")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let mut config: Config = Config::try_from(builder).expect("can build a valid config");
        config.fernet_tokens.key_repository = keys_dir.keep();

        let mut provider = FernetTokenProvider::new(config);
        provider.load_keys().await.unwrap();

        let token = FernetToken::Unscoped(UnscopedPayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["m8".into()],
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }
}
