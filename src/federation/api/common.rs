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

use serde_json::Value;

use openidconnect::IdTokenClaims;
use openidconnect::core::CoreGenderClaim;

use crate::api::common::{find_project_from_scope, get_domain};
use crate::api::error::KeystoneApiError;
use crate::auth::AuthzInfo;
use crate::common::types::Scope as ProviderScope;
use crate::federation::api::{
    error::OidcError,
    types::{AllOtherClaims, MappedUserData, MappedUserDataBuilder},
};
use crate::federation::types::{
    identity_provider::IdentityProvider as ProviderIdentityProvider,
    mapping::Mapping as ProviderMapping,
};
use crate::keystone::ServiceState;

/// Convert ProviderScope to AuthZ information
///
/// # Arguments
/// * `state`: The service state
/// * `scope`: The scope to extract the AuthZ information from
///
/// # Returns
/// * `Ok(AuthzInfo)`: The AuthZ information
/// * `Err(KeystoneApiError)`: An error if the scope is not valid
pub(super) async fn get_authz_info(
    state: &ServiceState,
    scope: Option<&ProviderScope>,
) -> Result<AuthzInfo, KeystoneApiError> {
    let authz_info = match scope {
        Some(ProviderScope::Project(scope)) => {
            if let Some(project) = find_project_from_scope(state, &scope.into()).await? {
                AuthzInfo::Project(project)
            } else {
                return Err(KeystoneApiError::Unauthorized(None));
            }
        }
        Some(ProviderScope::Domain(scope)) => {
            if let Ok(domain) = get_domain(state, scope.id.as_ref(), scope.name.as_ref()).await {
                AuthzInfo::Domain(domain)
            } else {
                return Err(KeystoneApiError::Unauthorized(None));
            }
        }
        Some(ProviderScope::System(_scope)) => todo!(),
        None => AuthzInfo::Unscoped,
    };
    authz_info.validate()?;
    Ok(authz_info)
}

/// Validate bound claims in the token
///
/// # Arguments
///
/// * `mapping` - The mapping to validate against
/// * `claims` - The claims to validate
/// * `claims_as_json` - The claims as json to validate
///
/// # Returns
///
/// * `Result<(), OidcError>`
pub(super) fn validate_bound_claims(
    mapping: &ProviderMapping,
    claims: &IdTokenClaims<AllOtherClaims, CoreGenderClaim>,
    claims_as_json: &Value,
) -> Result<(), OidcError> {
    if let Some(bound_subject) = &mapping.bound_subject
        && bound_subject != claims.subject().as_str()
    {
        return Err(OidcError::BoundSubjectMismatch {
            expected: bound_subject.to_string(),
            found: claims.subject().as_str().into(),
        });
    }
    if let Some(bound_audiences) = &mapping.bound_audiences {
        let mut bound_audiences_match: bool = false;
        for claim_audience in claims.audiences() {
            if bound_audiences.iter().any(|x| x == claim_audience.as_str()) {
                bound_audiences_match = true;
            }
        }
        if !bound_audiences_match {
            return Err(OidcError::BoundAudiencesMismatch {
                expected: bound_audiences.join(","),
                found: claims
                    .audiences()
                    .iter()
                    .map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            });
        }
    }
    if let Some(bound_claims) = &mapping.bound_claims
        && let Some(required_claims) = bound_claims.as_object()
    {
        for (claim, value) in required_claims.iter() {
            if !claims_as_json
                .get(claim)
                .map(|x| x == value)
                .is_some_and(|val| val)
            {
                return Err(OidcError::BoundClaimsMismatch {
                    claim: claim.to_string(),
                    expected: value.to_string(),
                    found: claims_as_json
                        .get(claim)
                        .map(|x| x.to_string())
                        .unwrap_or_default(),
                });
            }
        }
    }
    Ok(())
}

/// Map the user data using the referred mapping
///
/// # Arguments
/// * `idp` - The identity provider
/// * `mapping` - The mapping to use
/// * `claims_as_json` - The claims as json
///
/// # Returns
/// The mapped user data
pub(super) async fn map_user_data(
    _state: &ServiceState,
    idp: &ProviderIdentityProvider,
    mapping: &ProviderMapping,
    claims_as_json: &Value,
) -> Result<MappedUserData, OidcError> {
    let mut builder = MappedUserDataBuilder::default();
    //if let Some(token_user_id) = &mapping.token_user_id {
    //    // TODO: How to check that the user belongs to the right domain)
    //    if let Ok(Some(user)) = state
    //        .provider
    //        .get_identity_provider()
    //        .get_user(&state.db, token_user_id)
    //        .await
    //    {
    //        builder.unique_id(token_user_id.clone());
    //        builder.user_name(user.name.clone());
    //    } else {
    //        return Err(OidcError::UserNotFound(token_user_id.clone()))?;
    //    }
    //} else {
    builder.unique_id(
        claims_as_json
            .get(&mapping.user_id_claim)
            .and_then(|x| x.as_str())
            .ok_or_else(|| OidcError::UserIdClaimRequired(mapping.user_id_claim.clone()))?
            .to_string(),
    );

    builder.user_name(
        claims_as_json
            .get(&mapping.user_name_claim)
            .and_then(|x| x.as_str())
            .ok_or_else(|| OidcError::UserNameClaimRequired(mapping.user_name_claim.clone()))?,
    );
    //}

    builder.domain_id(
        mapping
            .domain_id
            .as_ref()
            .or(idp.domain_id.as_ref())
            .or(mapping
                .domain_id_claim
                .as_ref()
                .and_then(|claim| {
                    claims_as_json
                        .get(claim)
                        .and_then(|x| x.as_str().map(|v| v.to_string()))
                })
                .as_ref())
            .ok_or(OidcError::UserDomainUnbound)?,
    );

    if let Some(groups_claim) = &mapping.groups_claim
        && let Some(group_names_data) = &claims_as_json.get(groups_claim)
    {
        builder.group_names(
            group_names_data
                .as_array()
                .map(|names| {
                    names
                        .iter()
                        .map(|group| group.as_str().map(|v| v.to_string()))
                        .collect::<Option<Vec<_>>>()
                })
                .ok_or(OidcError::GroupsClaimNotArrayOfStrings)?,
        );
    }

    Ok(builder.build()?)
}
