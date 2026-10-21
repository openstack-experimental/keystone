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
//! # OAuth2 per-domain settings (ADR 0043 §1)

use serde::{Deserialize, Serialize};

pub use openstack_keystone_config::DpopMode;

/// Per-domain OAuth2 provider settings.
///
/// A domain without a stored record behaves as if [`DpopMode::Disabled`] were
/// set, so the record never has to be created for the default behavior.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OAuth2DomainSettings {
    /// Domain the settings belong to.
    pub domain_id: String,
    /// DPoP enforcement mode of the domain. The effective mode of a request
    /// is the strictest of the global, domain and client modes.
    #[serde(default)]
    pub dpop: DpopMode,
    /// Unix timestamp of the last change.
    pub updated_at: i64,
}

impl OAuth2DomainSettings {
    /// The settings of a domain that has no stored record.
    pub fn default_for(domain_id: impl Into<String>) -> Self {
        Self {
            domain_id: domain_id.into(),
            dpop: DpopMode::default(),
            updated_at: 0,
        }
    }
}

/// Update of the per-domain OAuth2 settings. `None` keeps the current value.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct OAuth2DomainSettingsUpdate {
    /// New DPoP enforcement mode of the domain.
    pub dpop: Option<DpopMode>,
}

impl OAuth2DomainSettings {
    /// Apply an update. The change time is stamped only when a value
    /// actually changes, so `updated_at` stays the time of the last real
    /// change.
    pub fn with_update(mut self, update: OAuth2DomainSettingsUpdate, now: i64) -> Self {
        if let Some(dpop) = update.dpop
            && dpop != self.dpop
        {
            self.dpop = dpop;
            self.updated_at = now;
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_disabled() {
        let settings = OAuth2DomainSettings::default_for("d1");
        assert_eq!(settings.dpop, DpopMode::Disabled);
        assert_eq!(settings.updated_at, 0);
    }

    #[test]
    fn test_with_update() {
        let base = OAuth2DomainSettings::default_for("d1");
        let kept = base
            .clone()
            .with_update(OAuth2DomainSettingsUpdate::default(), 10);
        assert_eq!(kept.dpop, DpopMode::Disabled);
        assert_eq!(kept.updated_at, 0);
        let same = base.clone().with_update(
            OAuth2DomainSettingsUpdate {
                dpop: Some(DpopMode::Disabled),
            },
            15,
        );
        assert_eq!(same.updated_at, 0);
        let raised = base.with_update(
            OAuth2DomainSettingsUpdate {
                dpop: Some(DpopMode::Required),
            },
            20,
        );
        assert_eq!(raised.dpop, DpopMode::Required);
        assert_eq!(raised.domain_id, "d1");
        assert_eq!(raised.updated_at, 20);
    }

    /// The mode is persisted: its encoding must not change with the config
    /// format or a variant rename.
    #[test]
    fn test_stored_dpop_mode_encoding_is_stable() {
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
}
