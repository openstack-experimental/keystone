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
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreRevocableToken,
    CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, EndpointMaybeSet, EndpointNotSet, EndpointSet, ExtraTokenFields,
    IdTokenFields, StandardErrorResponse, StandardTokenResponse,
};

pub mod auth;
pub mod identity_provider;
pub mod mapping;

pub use auth::*;
pub use identity_provider::*;
pub use mapping::*;

pub(super) type OidcIdTokenFields = IdTokenFields<
    AllOtherClaims,
    ExtraFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

pub(super) type OidcTokenResponse = StandardTokenResponse<OidcIdTokenFields, CoreTokenType>;

pub(super) type OidcClient<
    HasAuthUrl = EndpointSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointMaybeSet,
    HasUserInfoUrl = EndpointMaybeSet,
> = openidconnect::Client<
    AllOtherClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    OidcTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
    HasUserInfoUrl,
>;

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct AllOtherClaims(HashMap<String, serde_json::Value>);
impl AdditionalClaims for AllOtherClaims {}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct ExtraFields(HashMap<String, serde_json::Value>);
impl ExtraTokenFields for ExtraFields {}

#[derive(Builder, Debug, Clone)]
#[builder(setter(into))]
pub(super) struct MappedUserData {
    pub(super) unique_id: String,
    pub(super) user_name: String,
    pub(super) domain_id: String,
    #[builder(default)]
    pub(super) group_names: Option<Vec<String>>,
}
