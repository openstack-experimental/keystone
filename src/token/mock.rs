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
//! Internal mock structures for the [TokenProvider].

use async_trait::async_trait;
use mockall::mock;

use super::error::TokenProviderError;
use crate::auth::{AuthenticatedInfo, AuthzInfo};
use crate::config::Config;
use crate::keystone::ServiceState;

use super::{
    Token, TokenApi, TokenRestriction, TokenRestrictionCreate, TokenRestrictionListParameters,
    TokenRestrictionUpdate,
};

mock! {
    pub TokenProvider {
        pub fn new(cfg: &Config) -> Result<Self, TokenProviderError>;
    }

    #[async_trait]
    impl TokenApi for TokenProvider {
        async fn authenticate_by_token<'a>(
            &self,
            state: &ServiceState,
            credential: &'a str,
            allow_expired: Option<bool>,
            window_seconds: Option<i64>,
        ) -> Result<AuthenticatedInfo, TokenProviderError>;

        async fn validate_token<'a>(
            &self,
            state: &ServiceState,
            credential: &'a str,
            allow_expired: Option<bool>,
            window_seconds: Option<i64>,
        ) -> Result<Token, TokenProviderError>;

        #[mockall::concretize]
        fn issue_token(
            &self,
            authentication_info: AuthenticatedInfo,
            authz_info: AuthzInfo,
            token_restriction: Option<&TokenRestriction>
        ) -> Result<Token, TokenProviderError>;

        fn encode_token(&self, token: &Token) -> Result<String, TokenProviderError>;

        async fn populate_role_assignments(
            &self,
            state: &ServiceState,
            token: &mut Token,
        ) -> Result<(), TokenProviderError>;

        async fn expand_token_information(
            &self,
            state: &ServiceState,
            token: &Token,
        ) -> Result<Token, TokenProviderError>;

        async fn get_token_restriction<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            expand_roles: bool,
        ) -> Result<Option<TokenRestriction>, TokenProviderError>;

        async fn list_token_restrictions<'a>(
            &self,
            state: &ServiceState,
            params: &TokenRestrictionListParameters,
        ) -> Result<Vec<TokenRestriction>, TokenProviderError>;

        async fn create_token_restriction<'a>(
            &self,
            state: &ServiceState,
            restriction: TokenRestrictionCreate,
        ) -> Result<TokenRestriction, TokenProviderError>;

        async fn update_token_restriction<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            restriction: TokenRestrictionUpdate,
        ) -> Result<TokenRestriction, TokenProviderError>;

        async fn delete_token_restriction<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<(), TokenProviderError>;
    }

    impl Clone for TokenProvider {
        fn clone(&self) -> Self;
    }
}
