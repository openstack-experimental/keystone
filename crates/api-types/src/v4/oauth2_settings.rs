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
//! OAuth2 per-domain settings API types (ADR 0043 §1).

use serde::{Deserialize, Serialize};

/// DPoP enforcement mode (ADR 0043 §1).
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum DpopMode {
    /// Proofs are ignored and tokens are issued as bearer tokens.
    #[default]
    Disabled,
    /// A token is bound to the proof key whenever the client sends a proof.
    Optional,
    /// Requests without a valid proof are rejected.
    Required,
}

/// OAuth2 settings of a domain.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Oauth2DomainSettings {
    /// Domain the settings belong to.
    pub domain_id: String,
    /// DPoP enforcement mode of the domain. The effective mode of a request
    /// is the strictest of the global, domain and client modes.
    pub dpop: DpopMode,
    /// Unix timestamp of the last change; `0` while the domain has never
    /// been configured.
    pub updated_at: i64,
}

/// Update of the OAuth2 settings of a domain. A missing field keeps its
/// current value, so a misspelled field must be an error rather than a
/// silently ignored change.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct Oauth2DomainSettingsUpdate {
    /// New DPoP enforcement mode of the domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop: Option<DpopMode>,
}

/// Request body of `PUT /v4/oauth2/{domain_id}/settings`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct Oauth2DomainSettingsUpdateRequest {
    /// Settings to change.
    pub settings: Oauth2DomainSettingsUpdate,
}

/// Response body of the OAuth2 domain settings endpoints.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Oauth2DomainSettingsResponse {
    /// The settings of the domain.
    pub settings: Oauth2DomainSettings,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_wire_names() {
        for (mode, name) in [
            (DpopMode::Disabled, "disabled"),
            (DpopMode::Optional, "optional"),
            (DpopMode::Required, "required"),
        ] {
            assert_eq!(
                serde_json::to_value(mode).unwrap(),
                serde_json::Value::String(name.into())
            );
        }
    }

    #[test]
    fn test_update_keeps_missing_fields() {
        let req: Oauth2DomainSettingsUpdateRequest =
            serde_json::from_str(r#"{"settings": {}}"#).unwrap();
        assert_eq!(req.settings.dpop, None);
        let req: Oauth2DomainSettingsUpdateRequest =
            serde_json::from_str(r#"{"settings": {"dpop": "required"}}"#).unwrap();
        assert_eq!(req.settings.dpop, Some(DpopMode::Required));
        assert!(
            serde_json::from_str::<Oauth2DomainSettingsUpdateRequest>(
                r#"{"settings": {"dpop": "sometimes"}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn test_update_rejects_unknown_fields() {
        for body in [
            r#"{"settings": {"dpob": "required"}}"#,
            r#"{"settings": {"DPoP": "required"}}"#,
            r#"{"settings": {}, "extra": 1}"#,
        ] {
            assert!(
                serde_json::from_str::<Oauth2DomainSettingsUpdateRequest>(body).is_err(),
                "{body}"
            );
        }
    }
}
