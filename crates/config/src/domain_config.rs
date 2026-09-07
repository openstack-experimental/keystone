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
use serde::Deserialize;

/// `[domain_config]` section: which sources the per-domain configuration
/// resolver consults (ADR 0034 §2).
///
/// Both fields are `Option<bool>` on purpose. Unset means "inherit the
/// deprecated `[identity]` switch", so an existing deployment that only sets
/// the `[identity]` keys keeps its behaviour, defaults included:
///
/// - `from_files` unset  -> `[identity] domain_specific_drivers_enabled`
/// - `from_database` unset -> `[identity] domain_configurations_from_database`
///
/// When a `[domain_config]` key is set explicitly it wins; a conflicting
/// `[identity]` key set to a different value logs one `WARN` at construction
/// (see `openstack_keystone_core::domain_config::resolver`).
#[derive(Debug, Default, Deserialize, Clone)]
pub struct DomainConfigSection {
    /// Whether to consult the `fs` source (per-domain files under `[identity]
    /// domain_config_dir`). Unset inherits `[identity]
    /// domain_specific_drivers_enabled`.
    #[serde(default)]
    pub from_files: Option<bool>,

    /// Whether to consult the `sql` source (the `domain_config` table). Unset
    /// inherits `[identity] domain_configurations_from_database`.
    #[serde(default)]
    pub from_database: Option<bool>,
}

#[cfg(test)]
mod tests {
    use config::{Config, File, FileFormat};
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Default, Deserialize)]
    struct Wrapper {
        #[serde(default)]
        domain_config: DomainConfigSection,
    }

    fn parse(ini: &str) -> DomainConfigSection {
        Config::builder()
            .add_source(File::from_str(ini, FileFormat::Ini))
            .build()
            .unwrap()
            .try_deserialize::<Wrapper>()
            .unwrap()
            .domain_config
    }

    #[test]
    fn unset_keys_are_none() {
        let section = parse("[DEFAULT]\n");
        assert_eq!(section.from_files, None);
        assert_eq!(section.from_database, None);
    }

    #[test]
    fn explicit_false_round_trips_as_some_false() {
        let section = parse("[domain_config]\nfrom_files = false\nfrom_database = false\n");
        assert_eq!(section.from_files, Some(false));
        assert_eq!(section.from_database, Some(false));
    }

    #[test]
    fn explicit_true_round_trips_as_some_true() {
        let section = parse("[domain_config]\nfrom_files = true\nfrom_database = true\n");
        assert_eq!(section.from_files, Some(true));
        assert_eq!(section.from_database, Some(true));
    }
}
