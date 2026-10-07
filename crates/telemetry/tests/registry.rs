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

//! The `[otel]` and `[oslo_middleware_tracing]` sections registered with
//! `oslo-config`. An integration test, not a unit test:
//! `openstack-keystone-config` depends on this crate (through `cadf`), so
//! inside the unit-test binary the sections would be registered twice.

#![allow(clippy::unwrap_used)]

use std::io::Write;

use openstack_keystone_telemetry::{
    OsloMiddlewareTracingConfig, OtelConfig, OtlpProtocol, resolve,
};

/// A configuration file with the mandatory core sections plus `extra`.
async fn load(
    extra: &str,
) -> Result<oslo_config::Loaded<openstack_keystone_config::Config>, eyre::Report> {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(
        file,
        "[auth]\nmethods = []\n[database]\nconnection = \"foo\"\n{extra}"
    )
    .unwrap();
    oslo_config::load_snapshot_from::<openstack_keystone_config::Config>(file.path().into()).await
}

#[tokio::test]
async fn absent_sections_are_materialized_from_default() {
    let loaded = load("").await.unwrap();
    let otel = loaded.view().require::<OtelConfig>().unwrap().clone();
    assert!(otel.enabled.is_none());
    let alias = loaded
        .view()
        .require::<OsloMiddlewareTracingConfig>()
        .unwrap()
        .clone();
    // Neither section enables anything.
    assert!(resolve(&otel, &alias).unwrap().settings.is_none());
}

#[tokio::test]
async fn sections_are_read_from_the_file() {
    let loaded = load(
        "[otel]\nenabled = true\nsampling_rate = 0.5\nprotocol = grpc\n\
         [oslo_middleware_tracing]\nenabled = true\notlp_endpoint = http://tempo:4318\n",
    )
    .await
    .unwrap();
    let view = loaded.view();
    let r = resolve(
        view.require::<OtelConfig>().unwrap(),
        view.require::<OsloMiddlewareTracingConfig>().unwrap(),
    )
    .unwrap();
    let s = r.settings.unwrap();
    assert_eq!(s.protocol, OtlpProtocol::Grpc);
    assert_eq!(s.sampling_rate, 0.5);
    assert_eq!(s.endpoint.as_str(), "http://tempo:4318/");
}

/// `validate_with` runs `resolve` over both registered sections, so a bad
/// value fails the whole load.
#[tokio::test]
async fn invalid_section_fails_the_load() {
    assert!(load("[otel]\nsampling_rate = 7\n").await.is_err());
    assert!(
        load("[oslo_middleware_tracing]\nenabled = true\notlp_endpoint = ftp://x\n")
            .await
            .is_err()
    );
}
