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

use base64::Engine;
use byteorder::ReadBytesExt;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use fernet::MultiFernet;
use itertools::Itertools;
use rmp::{
    Marker,
    decode::{ValueReadError, read_marker, read_u8},
    encode::{write_array_len, write_pfix},
};
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fmt;
use std::io::{Cursor, Write};
use tracing::trace;

use crate::config::Config;
use crate::token::backend::TokenBackend;
use crate::token::{
    TokenProviderError,
    types::{
        application_credential::ApplicationCredentialPayload, domain_scoped::DomainScopePayload,
        federation_domain_scoped::FederationDomainScopePayload,
        federation_project_scoped::FederationProjectScopePayload,
        federation_unscoped::FederationUnscopedPayload, project_scoped::ProjectScopePayload,
        restricted::RestrictedPayload, unscoped::UnscopedPayload, *,
    },
};
use utils::FernetUtils;

mod application_credential;
mod restricted;
pub mod utils;

#[derive(Clone)]
pub struct FernetTokenProvider {
    config: Config,
    utils: FernetUtils,
    fernet: Option<MultiFernet>,
    /// Map of the configured authentication methods.
    auth_map: BTreeMap<u8, String>,
    /// Cached permutations of auth_methods to the payload code.
    auth_methods_code_cache: BTreeMap<u8, HashSet<String>>,
}

pub trait MsgPackToken {
    type Token;

    /// Construct MsgPack payload for the Token
    fn assemble<W: Write>(
        &self,
        _wd: &mut W,
        _fernet_provider: &FernetTokenProvider,
    ) -> Result<(), TokenProviderError> {
        Ok(())
    }

    /// Parse MsgPack payload into the Token
    fn disassemble(
        rd: &mut &[u8],
        fernet_provider: &FernetTokenProvider,
    ) -> Result<Self::Token, TokenProviderError>;
}

impl fmt::Debug for FernetTokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FernetTokenProvider").finish()
    }
}

/// Read the payload version
fn read_payload_token_type(rd: &mut &[u8]) -> Result<u8, TokenProviderError> {
    match read_marker(rd).map_err(ValueReadError::from)? {
        Marker::FixPos(dt) => Ok(dt),
        Marker::U8 => Ok(read_u8(rd)?),
        _ => Err(TokenProviderError::InvalidToken),
    }
}

/// Calculate possible combinations of the vector string elements.
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
    /// Construct new FernetTokenProvider
    pub fn new(config: Config) -> Self {
        let mut slf = Self {
            utils: FernetUtils {
                key_repository: config.fernet_tokens.key_repository.clone(),
                max_active_keys: config.fernet_tokens.max_active_keys,
            },
            config,
            fernet: None,
            auth_map: BTreeMap::new(),
            auth_methods_code_cache: BTreeMap::new(),
        };
        slf.reload_config();
        slf
    }

    pub fn reload_config(&mut self) {
        self.auth_map = BTreeMap::from_iter(
            self.config
                .auth
                .methods
                .iter()
                .enumerate()
                .map(|(k, v)| (1 << k, v.clone())),
        );
        self.set_auth_methods_cache_combinations();
    }

    fn set_auth_methods_cache_combinations(&mut self) {
        self.auth_methods_code_cache.clear();
        for auth_pairs in all_combinations(self.auth_map.values().cloned()) {
            let pair: HashSet<String> = HashSet::from_iter(auth_pairs.into_iter());
            self.encode_auth_methods(pair.clone())
                .ok()
                .map(|val| self.auth_methods_code_cache.insert(val, pair));
        }
    }

    /// Encode the list of auth_methods into a single integer
    #[tracing::instrument(level = "trace", skip(self, methods))]
    pub(crate) fn encode_auth_methods<I>(&self, methods: I) -> Result<u8, TokenProviderError>
    where
        I: IntoIterator<Item = String>,
    {
        let me: HashSet<String> = HashSet::from_iter(methods.into_iter());
        let res = self
            .auth_map
            .iter()
            .fold(0, |acc, (k, v)| acc + if me.contains(v) { *k } else { 0 });

        // TODO: Improve unit tests to ensure unsupported auth method immediately raises
        // error.
        if res == 0 {
            return Err(TokenProviderError::UnsupportedAuthMethods(
                me.iter().join(","),
            ));
        }
        Ok(res)
    }

    /// Decode the integer into the list of auth_methods
    #[tracing::instrument(level = "trace", skip(self))]
    pub(crate) fn decode_auth_methods(&self, value: u8) -> Result<Vec<String>, TokenProviderError> {
        if let Some(res) = self.auth_methods_code_cache.get(&value) {
            Ok(res.iter().cloned().collect())
        } else {
            trace!("Auth methods cache miss.");
            let mut results: Vec<String> = Vec::new();
            let mut auth: u8 = value;
            for (idx, name) in self.auth_map.iter() {
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
    fn decode(
        &self,
        rd: &mut &[u8],
        timestamp: DateTime<Utc>,
    ) -> Result<Token, TokenProviderError> {
        if let Marker::FixArray(_) = read_marker(rd).map_err(ValueReadError::from)? {
            let mut token: Token = match read_payload_token_type(rd)? {
                0 => Ok(UnscopedPayload::disassemble(rd, self)?.into()),
                1 => Ok(DomainScopePayload::disassemble(rd, self)?.into()),
                2 => Ok(ProjectScopePayload::disassemble(rd, self)?.into()),
                4 => Ok(FederationUnscopedPayload::disassemble(rd, self)?.into()),
                5 => Ok(FederationProjectScopePayload::disassemble(rd, self)?.into()),
                6 => Ok(FederationDomainScopePayload::disassemble(rd, self)?.into()),
                9 => Ok(ApplicationCredentialPayload::disassemble(rd, self)?.into()),
                11 => Ok(RestrictedPayload::disassemble(rd, self)?.into()),
                other => Err(TokenProviderError::InvalidTokenType(other)),
            }?;
            token.set_issued_at(timestamp);
            Ok(token.to_owned())
        } else {
            Err(TokenProviderError::InvalidToken)
        }
    }

    /// Encode Token as binary blob as MessagePack
    fn encode(&self, token: &Token) -> Result<Bytes, TokenProviderError> {
        let mut buf = vec![];
        match token {
            Token::Unscoped(data) => {
                write_array_len(&mut buf, 5)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 0)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            Token::DomainScope(data) => {
                write_array_len(&mut buf, 6)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 1)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            Token::ProjectScope(data) => {
                write_array_len(&mut buf, 6)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 2)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            Token::FederationUnscoped(data) => {
                write_array_len(&mut buf, 8)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 4)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            Token::FederationProjectScope(data) => {
                write_array_len(&mut buf, 9)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 5)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            Token::FederationDomainScope(data) => {
                write_array_len(&mut buf, 9)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 6)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            Token::ApplicationCredential(data) => {
                write_array_len(&mut buf, 7)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 9)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
            Token::Restricted(data) => {
                write_array_len(&mut buf, 9)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 11)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, self)?;
            }
        }
        Ok(buf.into())
    }

    /// Get MultiFernet initialized with repository keys
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn get_fernet(&self) -> Result<MultiFernet, TokenProviderError> {
        Ok(MultiFernet::new(
            self.utils.load_keys()?.into_iter().collect::<Vec<_>>(),
        ))
    }

    /// Load fernet keys from FS
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn load_keys(&mut self) -> Result<(), TokenProviderError> {
        self.fernet = Some(self.get_fernet()?);
        Ok(())
    }

    /// Decrypt the token
    ///
    /// 1. Decrypt as Fernet
    /// 2. Unpack MessagePack payload
    pub fn decrypt(&self, credential: &str) -> Result<Token, TokenProviderError> {
        // TODO: Implement fernet keys change watching. Keystone loads them from FS on
        // every request and in the best case it costs 15µs.
        let fernet = match &self.fernet {
            Some(f) => f,
            None => &self.get_fernet()?,
        };
        let payload = fernet.decrypt(credential)?;

        self.decode(&mut payload.as_slice(), get_fernet_timestamp(credential)?)
    }

    /// Encrypt the token
    pub fn encrypt(&self, token: &Token) -> Result<String, TokenProviderError> {
        let payload = self.encode(token)?;
        let res = match &self.fernet {
            Some(fernet) => fernet.encrypt(&payload),
            _ => self.get_fernet()?.encrypt(&payload),
        };
        Ok(res)
    }
}

impl TokenBackend for FernetTokenProvider {
    /// Set config
    fn set_config(&mut self, config: Config) {
        self.config = config;
        self.reload_config();
    }

    /// Decrypt the token
    #[tracing::instrument(level = "trace", skip(self, credential))]
    fn decode(&self, credential: &str) -> Result<Token, TokenProviderError> {
        self.decrypt(credential)
    }

    /// Encrypt the token
    #[tracing::instrument(level = "trace", skip(self, token))]
    fn encode(&self, token: &Token) -> Result<String, TokenProviderError> {
        self.encrypt(token)
    }
}

/// Decode the fernet payload as Base64_urlsafe.
fn b64_decode_url(input: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input.trim_end_matches('='))
}

/// Get the fernet payload creation timestamp.
///
/// Extract the payload creation timestamp in the UTC.
fn get_fernet_timestamp(payload: &str) -> Result<DateTime<Utc>, TokenProviderError> {
    let data = match b64_decode_url(payload) {
        Ok(data) => data,
        Err(_) => return Err(fernet::DecryptionError)?,
    };

    let mut input = Cursor::new(data);

    match input.read_u8() {
        Ok(0x80) => {}
        _ => return Err(fernet::DecryptionError)?,
    }

    input
        .read_u64::<byteorder::BigEndian>()
        .map_err(|_| TokenProviderError::FernetDecryption {
            source: fernet::DecryptionError,
        })
        .and_then(|val| {
            TryInto::try_into(val).map_err(|err| TokenProviderError::TokenTimestampOverflow {
                value: val,
                source: err,
            })
        })
        .and_then(|val| {
            DateTime::from_timestamp_secs(val).ok_or_else(|| TokenProviderError::FernetDecryption {
                source: fernet::DecryptionError,
            })
        })
}

// Conditionally expose the function when the 'bench_internals' feature is
// enabled
#[cfg(feature = "bench_internals")]
pub fn bench_get_fernet_timestamp(payload: &str) -> Result<DateTime<Utc>, TokenProviderError> {
    get_fernet_timestamp(payload)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use chrono::{Local, SubsecRound};
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    use uuid::Uuid;

    pub(super) fn setup_config() -> Config {
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

    fn discard_issued_at(mut token: Token) -> Token {
        token.set_issued_at(Default::default());
        token
    }

    #[tokio::test]
    async fn test_decrypt_unscoped() {
        let token = "gAAAAABnt12vpnYCuUxl1lWQfTxwkBcZcgdK5wYons4BFHxxZLk326To5afinp29in7f5ZHR5K61Pl2voIjfbPKlL51KempshD4shfSje4RutbeXq-NT498eEcorzige5XBYGaoWuDTOKEDH2eXCMHhw9722j9iPP3Z4r_1Zlmcqq1n2tndmvsA";

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().unwrap();

        if let Token::Unscoped(decrypted) = provider.decrypt(token).unwrap() {
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
        let token = Token::Unscoped(UnscopedPayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_domain() {
        let token = "gAAAAABnt16C_ve4dDc7TeU857pwTXGJfGqNA4uJ308_2o_F9T_8WenNBatll0Q36wGz79dSI6RQnuN2PbK17wxQbn9jXscDh2ie3ZrW-WL5gG3gWK6FiPleAiU3kJN5mkskViJOIN-ZpP2B15fmZiYijelQ9TQuhQ";

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().unwrap();

        if let Token::DomainScope(decrypted) = provider.decrypt(token).unwrap() {
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
        let token = Token::DomainScope(DomainScopePayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            domain_id: Uuid::new_v4().simple().to_string(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_project() {
        let token = "gAAAAABns2ixy75K_KfoosWLrNNqG6KW8nm3Xzv0_2dOx8ODWH7B8i2g8CncGLO6XBEH_TYLg83P6XoKQ5bU8An8Kqgw9WX3bvmEQXphnwPM6aRAOQUSdVhTlUm_8otDG9BS2rc70Q7pfy57S3_yBgimy-174aKdP8LPusvdHZsQPEJO9pfeXWw";

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().unwrap();

        if let Token::ProjectScope(decrypted) = provider.decrypt(token).unwrap() {
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
        let token = Token::ProjectScope(ProjectScopePayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            project_id: Uuid::new_v4().simple().to_string(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_federation_unscoped() {
        let token = "gAAAAABoMdfwBgwjAfYCp3RisL_XKSdGKmBqg7ia8jkfsKIXnap_bQ5gUTZGwgEERlpFKzbwpkV-cpiFDuhe9RAnCtbQxEhP7Rg1vt1VLm8afGTulDaLclqot2NC-BONFO2k3V3KyIa-Xrq0mCEGOk-BhNZy2C6iwrWanPCjCuZrWCq4FBirtMs2vrnZPWG5FTGqqkvdQvGj";

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().unwrap();

        if let Token::FederationUnscoped(decrypted) = provider.decrypt(token).unwrap() {
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
        let token = Token::FederationUnscoped(FederationUnscopedPayload {
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
        provider.load_keys().unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_federation_project_scope() {
        let token = "gAAAAABoNdYE5zCP0qQtHqhdbZHQ7YdLvfDlUTpLou8FJFoMKsd4I9jyVyaWrluYXKXofnwzemA-wybhtbNruwqDYH-wmHdMlgYuZyy21o8ylphU5yd2b-5KvGpXo61fTVTzhdHFTzJKVit_7Lcwq0S45xQ9x14sVRd870NEwfmOvUVR5BGzmnpFLvWtkaPSpbxMAzfn_NSC";

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().unwrap();

        if let Token::FederationProjectScope(decrypted) = provider.decrypt(token).unwrap() {
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
        let token = Token::FederationProjectScope(FederationProjectScopePayload {
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
        provider.load_keys().unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_federation_domain_scope() {
        let token = "gAAAAABoNddwFaB2Oq26-4f8nRK3Bph7-QsIh30Rbefbb78owJXaQcjNQm5Qq1gHouS6JSqgfpdna3ML1vdTVnVnFScX-T-CZ-CqtBPUuEBHFEzdNBDKQHloYajZ2sknwbe_uIs1SDS9tBFLvkVth1eVjDhdEawINHjUCFhNPObZKas5V0j7bsvChNeZBKsznruJwCtcrWr5";

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().unwrap();

        if let Token::FederationDomainScope(decrypted) = provider.decrypt(token).unwrap() {
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
        let token = Token::FederationDomainScope(FederationDomainScopePayload {
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

        let config = crate::tests::token::setup_config();
        let mut provider = FernetTokenProvider::new(config);
        provider.load_keys().unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_application_credential() {
        let token = "gAAAAABnt11m57ZlI9JU0g2BKJw2EN-InbAIijcIG7SxvPATntgTlcTMwha-Fh7isNNIwDq2WaWglV1nYgftfoUK245ZnEJ0_gXaIhl6COhNommYv2Bs9PnJqfgrrxrIrB8rh4pfeyCtMkv5ePYgFFPyRFE37l3k7qL5p7qVhYT37yT1-K5lYAV0f6Vy70h3KX1HO0m6Rl90";

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().unwrap();

        if let Token::ApplicationCredential(decrypted) = provider.decrypt(token).unwrap() {
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
        let token = Token::ApplicationCredential(ApplicationCredentialPayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["application_credential".into()],
            project_id: Uuid::new_v4().simple().to_string(),
            application_credential_id: Uuid::new_v4().simple().to_string(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut provider = FernetTokenProvider::new(setup_config());
        provider.load_keys().unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_restricted_roundtrip() {
        let token = Token::Restricted(RestrictedPayload {
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
        provider.load_keys().unwrap();

        let encrypted = provider.encrypt(&token).unwrap();
        let dec_token = discard_issued_at(provider.decrypt(&encrypted).unwrap());
        assert_eq!(token, dec_token);
    }
}
