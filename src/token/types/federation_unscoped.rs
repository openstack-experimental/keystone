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

use chrono::{DateTime, Utc};
use derive_builder::Builder;
use rmp::{decode::read_pfix, encode::write_pfix};
use serde::Serialize;
use std::io::Write;
use validator::Validate;

use crate::identity::types::UserResponse;
use crate::token::types::common;
use crate::token::{
    backend::fernet::{FernetTokenProvider, MsgPackToken, utils},
    error::TokenProviderError,
    types::Token,
};

/// Federated unscoped token payload
#[derive(Builder, Clone, Debug, Default, PartialEq, Serialize, Validate)]
#[builder(setter(into))]
pub struct FederationUnscopedPayload {
    #[validate(length(min = 1, max = 64))]
    pub user_id: String,

    #[builder(default, setter(name = _methods))]
    #[validate(length(min = 1))]
    pub methods: Vec<String>,

    #[builder(default, setter(name = _audit_ids))]
    #[validate(custom(function = "common::validate_audit_ids"))]
    pub audit_ids: Vec<String>,
    pub expires_at: DateTime<Utc>,

    #[validate(length(min = 1, max = 64))]
    pub idp_id: String,

    #[validate(length(min = 1, max = 64))]
    pub protocol_id: String,
    pub group_ids: Vec<String>,

    #[builder(default)]
    pub issued_at: DateTime<Utc>,
    #[builder(default)]
    pub user: Option<UserResponse>,
}

impl FederationUnscopedPayloadBuilder {
    pub fn methods<I, V>(&mut self, iter: I) -> &mut Self
    where
        I: Iterator<Item = V>,
        V: Into<String>,
    {
        self.methods
            .get_or_insert_with(Vec::new)
            .extend(iter.map(Into::into));
        self
    }

    pub fn audit_ids<I, V>(&mut self, iter: I) -> &mut Self
    where
        I: Iterator<Item = V>,
        V: Into<String>,
    {
        self.audit_ids
            .get_or_insert_with(Vec::new)
            .extend(iter.map(Into::into));
        self
    }
}

impl From<FederationUnscopedPayload> for Token {
    fn from(value: FederationUnscopedPayload) -> Self {
        Self::FederationUnscoped(value)
    }
}

impl MsgPackToken for FederationUnscopedPayload {
    type Token = Self;

    fn assemble<W: Write>(
        &self,
        wd: &mut W,
        fernet_provider: &FernetTokenProvider,
    ) -> Result<(), TokenProviderError> {
        utils::write_uuid(wd, &self.user_id)?;
        write_pfix(
            wd,
            fernet_provider.encode_auth_methods(self.methods.clone())?,
        )
        .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
        utils::write_list_of_uuids(wd, self.group_ids.iter())?;
        utils::write_uuid(wd, &self.idp_id)?;
        utils::write_str(wd, &self.protocol_id)?;
        utils::write_time(wd, self.expires_at)?;
        utils::write_audit_ids(wd, self.audit_ids.clone())?;

        Ok(())
    }

    fn disassemble(
        rd: &mut &[u8],
        fernet_provider: &FernetTokenProvider,
    ) -> Result<Self::Token, TokenProviderError> {
        // Order of reading is important
        let user_id = utils::read_uuid(rd)?;
        let methods: Vec<String> = fernet_provider
            .decode_auth_methods(read_pfix(rd)?)?
            .into_iter()
            .collect();
        let group_ids = utils::read_list_of_uuids(rd)?;
        let idp_id = utils::read_uuid(rd)?;
        let protocol_id = utils::read_str(rd)?;
        let expires_at = utils::read_time(rd)?;
        let audit_ids: Vec<String> = utils::read_audit_ids(rd)?.into_iter().collect();
        Ok(Self {
            user_id,
            methods,
            expires_at,
            audit_ids,
            group_ids: group_ids.into_iter().collect(),
            idp_id,
            protocol_id,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Local, SubsecRound};
    use uuid::Uuid;

    use super::*;
    use crate::token::tests::setup_config;

    #[test]
    fn test_roundtrip() {
        let token = FederationUnscopedPayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["openid".into()],
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            group_ids: vec!["g1".into()],
            idp_id: "idp_id".into(),
            protocol_id: "proto".into(),
            ..Default::default()
        };

        let provider = FernetTokenProvider::new(setup_config());

        let mut buf = vec![];
        token.assemble(&mut buf, &provider).unwrap();
        let encoded_buf = buf.clone();
        let decoded =
            FederationUnscopedPayload::disassemble(&mut encoded_buf.as_slice(), &provider).unwrap();
        assert_eq!(token, decoded);
    }
}
