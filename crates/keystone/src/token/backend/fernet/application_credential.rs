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

use rmp::{decode::read_pfix, encode::write_pfix};
use std::io::Write;

use crate::token::{
    backend::fernet::{FernetTokenProvider, MsgPackToken, utils},
    error::TokenProviderError,
    types::ApplicationCredentialPayload,
};

impl MsgPackToken for ApplicationCredentialPayload {
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
        utils::write_uuid(wd, &self.project_id)?;
        utils::write_time(wd, self.expires_at)?;
        utils::write_audit_ids(wd, self.audit_ids.clone())?;
        utils::write_uuid(wd, &self.application_credential_id)?;

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
        let project_id = utils::read_uuid(rd)?;
        let expires_at = utils::read_time(rd)?;
        let audit_ids: Vec<String> = utils::read_audit_ids(rd)?.into_iter().collect();
        let application_credential_id = utils::read_uuid(rd)?;

        Ok(Self {
            user_id,
            methods,
            expires_at,
            audit_ids,
            project_id,
            application_credential_id,
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
        let token = ApplicationCredentialPayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            project_id: Uuid::new_v4().simple().to_string(),
            application_credential_id: Uuid::new_v4().simple().to_string(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        };

        let provider = FernetTokenProvider::new(setup_config());

        let mut buf = vec![];
        token.assemble(&mut buf, &provider).unwrap();
        let encoded_buf = buf.clone();
        let decoded =
            ApplicationCredentialPayload::disassemble(&mut encoded_buf.as_slice(), &provider)
                .unwrap();
        assert_eq!(token, decoded);
    }
}
