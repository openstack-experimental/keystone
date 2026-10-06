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

//! Golden-file assertions for rendered Prometheus exposition text (ADR 0040).
//!
//! The `/metrics` series names, label sets, HELP/TYPE lines and bucket layout
//! are a public contract (`deploy/prometheus/alert_rules.yaml`, ADR 0031). The
//! OpenTelemetry migration must not change them, so every subsystem renders a
//! deterministic fixture and compares it with a checked-in file under
//! `tests/golden/<name>.prom` of the calling crate.
//!
//! Set `UPDATE_GOLDEN=1` to (re)write the files instead of asserting. A diff
//! in a golden file is a breaking change for scrapers and needs a reviewer to
//! confirm it is intended.

use std::path::{Path, PathBuf};

/// Environment variable that switches [`assert_golden`] to rewrite mode.
pub const UPDATE_ENV: &str = "UPDATE_GOLDEN";

/// Path of the golden file `name` for the crate rooted at `manifest_dir`.
pub fn golden_path(manifest_dir: &str, name: &str) -> PathBuf {
    Path::new(manifest_dir)
        .join("tests")
        .join("golden")
        .join(format!("{name}.prom"))
}

/// Compares `actual` with the golden file (or rewrites it, see [`UPDATE_ENV`]).
///
/// Prefer the [`assert_golden!`](crate::assert_golden) macro, which fills in
/// the calling crate's `CARGO_MANIFEST_DIR`.
pub fn assert_golden_at(manifest_dir: &str, name: &str, actual: &str) {
    let path = golden_path(manifest_dir, name);
    if std::env::var_os(UPDATE_ENV).is_some() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|e| panic!("create {}: {e}", parent.display()));
        }
        std::fs::write(&path, actual).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read golden file {} ({e}); run with {UPDATE_ENV}=1 to create it",
            path.display()
        )
    });
    assert_eq!(
        expected,
        actual,
        "exposition text differs from {}; if the change is intended run with {UPDATE_ENV}=1 \
         and review the diff (series names are a scrape/alerting contract)",
        path.display()
    );
}

/// `assert_golden!("name", text)` pins `text` to `tests/golden/name.prom`.
#[macro_export]
macro_rules! assert_golden {
    ($name:expr, $actual:expr) => {
        $crate::golden::assert_golden_at(env!("CARGO_MANIFEST_DIR"), $name, &$actual)
    };
}
