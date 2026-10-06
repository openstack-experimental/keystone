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
//! Section registry tests with fake sections.
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::path::PathBuf;

use oslo_config::{
    ConfigError, ConfigSection, ConfigView, CoreSchema, LoadCtx, SectionBag, SourceSpec,
    assert_registered, check_registry, load_snapshot_from, register_section,
};
use serde::Deserialize;
use serial_test::serial;
use tempfile::NamedTempFile;

#[derive(Debug, Default, Deserialize)]
struct Core {
    #[serde(default)]
    default: CoreDefault,
}

#[derive(Debug, Default, Deserialize)]
struct CoreDefault {
    #[serde(default)]
    debug: bool,
}

impl CoreSchema for Core {
    fn source() -> SourceSpec {
        SourceSpec {
            env_prefix: "FAKE",
            env_prefix_separator: "_",
            env_separator: "__",
            site_vars_env: "FAKE_SITE_VARS_FILE",
        }
    }

    fn reserved_sections() -> &'static [&'static str] {
        &["default"]
    }
}

#[derive(Debug, Deserialize, PartialEq)]
struct Optional {
    #[serde(default = "default_timeout")]
    timeout: u32,
    #[serde(default)]
    marker_file: Option<PathBuf>,
}

fn default_timeout() -> u32 {
    5
}

impl Default for Optional {
    fn default() -> Self {
        Self {
            timeout: default_timeout(),
            marker_file: None,
        }
    }
}

impl ConfigSection for Optional {
    const NAME: &'static str = "fake_optional";

    fn finish(&mut self, ctx: &LoadCtx) -> Result<(), ConfigError> {
        assert!(!ctx.config_path.as_os_str().is_empty());
        Ok(())
    }

    fn watch_files(&self) -> Vec<PathBuf> {
        self.marker_file.iter().cloned().collect()
    }
}
register_section!(Optional, default);

#[derive(Debug, Deserialize)]
struct Required {
    endpoint: String,
}

impl ConfigSection for Required {
    const NAME: &'static str = "fake_required";

    fn validate_with(&self, sections: &SectionBag) -> Result<(), ConfigError> {
        if self.endpoint == "forbidden" {
            return Err(eyre::eyre!("endpoint is forbidden"));
        }
        // Sibling sections are visible in the second pass.
        assert!(sections.get::<Optional>().is_some());
        Ok(())
    }
}
register_section!(Required);

fn conf(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f
}

#[tokio::test]
#[serial]
async fn optional_materialized_from_default_required_absent() {
    let f = conf("[default]\ndebug = true\n");
    let loaded = load_snapshot_from::<Core>(f.path().to_path_buf())
        .await
        .unwrap();
    let view: ConfigView<'_, Core> = loaded.view();
    assert!(view.default.debug, "core is reachable through Deref");
    assert_eq!(view.section::<Optional>(), Some(&Optional::default()));
    assert!(view.section::<Required>().is_none());
    let err = view.require::<Required>().unwrap_err();
    assert!(err.to_string().contains("fake_required"));
}

#[tokio::test]
#[serial]
async fn sections_parsed_from_file_and_env_override() {
    let f = conf("[fake_optional]\ntimeout = 9\n[fake_required]\nendpoint = \"a\"\n");
    temp_env::async_with_vars(
        [("FAKE_FAKE_REQUIRED__ENDPOINT", Some("from-env"))],
        async {
            let loaded = load_snapshot_from::<Core>(f.path().to_path_buf())
                .await
                .unwrap();
            assert_eq!(loaded.sections.get::<Optional>().unwrap().timeout, 9);
            assert_eq!(
                loaded.sections.get::<Required>().unwrap().endpoint,
                "from-env"
            );
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn invalid_section_fails_load() {
    let f = conf("[fake_optional]\ntimeout = \"nan\"\n");
    let err = load_snapshot_from::<Core>(f.path().to_path_buf())
        .await
        .err()
        .unwrap();
    assert!(format!("{err:#}").contains("fake_optional"));
}

#[tokio::test]
#[serial]
async fn validate_pass_runs() {
    let f = conf("[fake_required]\nendpoint = \"forbidden\"\n");
    let err = load_snapshot_from::<Core>(f.path().to_path_buf())
        .await
        .err()
        .unwrap();
    assert!(format!("{err:#}").contains("forbidden"));
}

#[tokio::test]
#[serial]
async fn section_watch_files_collected() {
    let f = conf("[fake_optional]\nmarker_file = \"/tmp/marker\"\n");
    let loaded = load_snapshot_from::<Core>(f.path().to_path_buf())
        .await
        .unwrap();
    assert_eq!(
        loaded.sections.get::<Optional>().unwrap().marker_file,
        Some(PathBuf::from("/tmp/marker"))
    );
}

#[test]
fn registry_rules() {
    check_registry(&["default"]).unwrap();
    assert!(check_registry(&["fake_optional"]).is_err());
    assert_registered(&["fake_optional", "fake_required"]).unwrap();
    assert!(assert_registered(&["missing"]).is_err());
}
