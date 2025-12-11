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

use crate::token::types::validators;
use crate::identity::types::UserResponse;
use crate::token::{
    backend::fernet::{FernetTokenProvider, MsgPackToken, utils},
    error::TokenProviderError,
    types::Token,
};

#[derive(Builder, Clone, Debug, Default, PartialEq, Serialize, Validate)]
#[builder(setter(into))]
pub struct UnscopedPayload {
    #[validate(length(min = 1, max = 64))]
    pub user_id: String,

    #[builder(default, setter(name = _methods))]
    #[validate(length(min = 1))]
    pub methods: Vec<String>,

    #[builder(default, setter(name = _audit_ids))]
    #[validate(custom(function = "validators::validate_audit_ids"))]
    pub audit_ids: Vec<String>,

    #[validate(custom(function = "validators::validate_future_datetime"))]
    pub expires_at: DateTime<Utc>,

    #[builder(default)]
    #[validate(custom(function = "validators::validate_issued_datetime"))]
    pub issued_at: DateTime<Utc>,

    #[builder(default)]
    pub user: Option<UserResponse>,
}

impl UnscopedPayloadBuilder {
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

impl From<UnscopedPayload> for Token {
    fn from(value: UnscopedPayload) -> Self {
        Self::Unscoped(value)
    }
}

impl MsgPackToken for UnscopedPayload {
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
        utils::write_time(wd, self.expires_at)?;
        utils::write_audit_ids(wd, self.audit_ids.clone())?;

        Ok(())
    }

    fn disassemble(
        rd: &mut &[u8],
        fernet_provider: &FernetTokenProvider,
    ) -> Result<Self::Token, TokenProviderError> {
        // Order of writing is important
        let user_id = utils::read_uuid(rd)?;
        let methods: Vec<String> = fernet_provider
            .decode_auth_methods(read_pfix(rd)?)?
            .into_iter()
            .collect();
        let expires_at = utils::read_time(rd)?;
        let audit_ids: Vec<String> = utils::read_audit_ids(rd)?.into_iter().collect();
        Ok(Self::Token {
            user_id,
            methods,
            expires_at,
            audit_ids,
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
        let token = UnscopedPayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        };

        let provider = FernetTokenProvider::new(setup_config());

        let mut buf = vec![];
        token.assemble(&mut buf, &provider).unwrap();
        let encoded_buf = buf.clone();
        let decoded = UnscopedPayload::disassemble(&mut encoded_buf.as_slice(), &provider).unwrap();
        assert_eq!(token, decoded);
    }
}