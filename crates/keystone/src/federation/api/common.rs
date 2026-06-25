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

use openstack_keystone_core_types::federation::{
    IdentityProvider as ProviderIdentityProvider, Mapping as ProviderMapping,
};

use crate::federation::api::{
    error::OidcError,
    types::{MappedUserData, MappedUserDataBuilder},
};
use crate::keystone::ServiceState;

/// Validate bound claims against the decoded token claims.
pub(super) fn validate_bound_claims(
    mapping: &ProviderMapping,
    claims_as_json: &Value,
) -> Result<(), OidcError> {
    if let Some(bound_subject) = &mapping.bound_subject {
        let actual_sub = claims_as_json
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OidcError::BoundSubjectMismatch {
                expected: bound_subject.clone(),
                found: "<missing>".to_string(),
            })?;
        if bound_subject != actual_sub {
            return Err(OidcError::BoundSubjectMismatch {
                expected: bound_subject.to_string(),
                found: actual_sub.to_string(),
            });
        }
    }

    if let Some(bound_audiences) = &mapping.bound_audiences {
        let claim_audiences: Vec<String> = match claims_as_json.get("aud") {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect(),
            _ => vec![],
        };
        let matched = claim_audiences
            .iter()
            .any(|a| bound_audiences.iter().any(|b| b == a));
        if !matched {
            return Err(OidcError::BoundAudiencesMismatch {
                expected: bound_audiences.join(","),
                found: claim_audiences.join(","),
            });
        }
    }

    for (claim, value) in mapping.bound_claims.iter() {
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
    Ok(())
}

/// Map the user data using the referred mapping.
pub(super) async fn map_user_data(
    _state: &ServiceState,
    idp: &ProviderIdentityProvider,
    mapping: &ProviderMapping,
    claims_as_json: &Value,
) -> Result<MappedUserData, OidcError> {
    let mut builder = MappedUserDataBuilder::default();

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
