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
//! OAuth2 per-domain settings conversion implementations.

use openstack_keystone_core_types::oauth2_client as core;

use crate::v4::oauth2_settings as api;

impl From<api::DpopMode> for core::DpopMode {
    fn from(value: api::DpopMode) -> Self {
        match value {
            api::DpopMode::Disabled => Self::Disabled,
            api::DpopMode::Optional => Self::Optional,
            api::DpopMode::Required => Self::Required,
        }
    }
}

impl From<core::DpopMode> for api::DpopMode {
    fn from(value: core::DpopMode) -> Self {
        match value {
            core::DpopMode::Disabled => Self::Disabled,
            core::DpopMode::Optional => Self::Optional,
            core::DpopMode::Required => Self::Required,
        }
    }
}

impl From<core::OAuth2DomainSettings> for api::Oauth2DomainSettings {
    fn from(value: core::OAuth2DomainSettings) -> Self {
        Self {
            domain_id: value.domain_id,
            dpop: value.dpop.into(),
            updated_at: value.updated_at,
        }
    }
}

impl From<api::Oauth2DomainSettingsUpdate> for core::OAuth2DomainSettingsUpdate {
    fn from(value: api::Oauth2DomainSettingsUpdate) -> Self {
        Self {
            dpop: value.dpop.map(Into::into),
            expected_dpop: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_roundtrip() {
        for mode in [
            api::DpopMode::Disabled,
            api::DpopMode::Optional,
            api::DpopMode::Required,
        ] {
            assert_eq!(api::DpopMode::from(core::DpopMode::from(mode)), mode);
        }
    }

    #[test]
    fn test_settings_conversion() {
        let settings = api::Oauth2DomainSettings::from(core::OAuth2DomainSettings {
            domain_id: "d1".into(),
            dpop: core::DpopMode::Optional,
            updated_at: 7,
        });
        assert_eq!(settings.domain_id, "d1");
        assert_eq!(settings.dpop, api::DpopMode::Optional);
        assert_eq!(settings.updated_at, 7);
        let update = core::OAuth2DomainSettingsUpdate::from(api::Oauth2DomainSettingsUpdate {
            dpop: Some(api::DpopMode::Required),
        });
        assert_eq!(update.dpop, Some(core::DpopMode::Required));
    }
}
