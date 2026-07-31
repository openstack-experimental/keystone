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
use std::path::PathBuf;
use url::Url;

/// Default configuration section.
///
/// The `log_rotation_type`/`log_rotate_interval`/`log_rotate_interval_type`/
/// `max_logfile_count` fields below mirror a subset of `oslo_log`'s options
/// (also configured under `[DEFAULT]` in python-keystone). They are kept as
/// plain fields here rather than nested under a `#[serde(flatten)]`d
/// sub-struct: `config-rs` reads INI values as strings, and its `flatten`
/// support buffers each value through serde's generic `Content` type before
/// re-deserializing it into the target field, which cannot coerce a
/// string-typed numeric value into an integer — so a flattened numeric
/// field would fail to parse from a real `keystone.conf` file.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct DefaultSection {
    /// If set to true, the logging level for the file will be set to DEBUG
    /// instead of the default INFO level.
    #[serde(default)]
    pub debug: bool,

    // Directory to be used for writing log files.
    pub log_dir: Option<PathBuf>,

    /// Public endpoint.
    pub public_endpoint: Option<Url>,

    /// Log output directly to the systemd journal (native journald
    /// protocol), instead of relying on a container/service manager to
    /// capture and forward stderr. Mutually exclusive with `use_stderr`:
    /// enabling both under a container log driver that also forwards
    /// stderr to journald (e.g. podman `--log-driver=journald`) produces
    /// duplicate entries in `journalctl` — one from the native write, one
    /// from the driver capturing the stderr text.
    #[serde(default)]
    pub use_journal: bool,

    /// Log output to standard error.
    #[serde(default)]
    pub use_stderr: bool,

    /// Global default page size, used when a provider has no
    /// `list_limit` of its own and the client omits `limit`. Mirrors
    /// python-keystone's `[DEFAULT] list_limit`.
    pub list_limit: Option<u64>,

    /// Global absolute cap on `limit`, used when a provider has no
    /// `max_list_limit` of its own. Mirrors python-keystone's
    /// `[DEFAULT] max_db_limit`.
    pub max_db_limit: Option<u64>,

    /// Log rotation strategy for [`log_dir`](Self::log_dir). Mirrors
    /// oslo_log's `log_rotation_type`.
    ///
    /// oslo_log also exposes a `size`-based rotation strategy
    /// (`log_rotation_type = size`, `max_logfile_size_mb`); the underlying
    /// rolling-file-appender only rotates on a fixed time period, not file
    /// size, so `size` is intentionally not an accepted value here rather
    /// than being silently accepted and ignored.
    #[serde(default)]
    pub log_rotation_type: LogRotationType,

    /// Number of `log_rotate_interval_type` units between rotations.
    /// Mirrors oslo_log's `log_rotate_interval`. The underlying
    /// rolling-file-appender only supports rotating on every single unit
    /// (matching oslo_log's own default of `1`); any other value is logged
    /// as a startup warning and treated as `1`. Only used when
    /// `log_rotation_type = "interval"`.
    pub log_rotate_interval: Option<u32>,

    /// Unit for `log_rotate_interval`. Mirrors oslo_log's
    /// `log_rotate_interval_type`. Only used when `log_rotation_type =
    /// "interval"`.
    #[serde(default)]
    pub log_rotate_interval_type: LogRotateIntervalType,

    /// Maximum number of rotated log files to retain; older files beyond
    /// this count are deleted on rotation. Mirrors oslo_log's
    /// `max_logfile_count`. Only used when `log_rotation_type =
    /// "interval"`.
    pub max_logfile_count: Option<usize>,
}

/// Log rotation strategy. Mirrors oslo_log's `log_rotation_type`.
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogRotationType {
    /// No rotation: a single, ever-growing log file. Matches oslo_log's own
    /// default.
    #[default]
    None,
    /// Rotate on a fixed time interval; see
    /// [`DefaultSection::log_rotate_interval_type`].
    Interval,
}

/// Unit for [`DefaultSection::log_rotate_interval`]. Mirrors oslo_log's
/// `log_rotate_interval_type`.
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogRotateIntervalType {
    /// Rotate every minute.
    Minutes,
    /// Rotate every hour.
    Hours,
    /// Rotate every day, matching oslo_log's own default.
    #[default]
    Days,
    /// Rotate at midnight; the rolling-file-appender treats this the same
    /// as `days`.
    Midnight,
}

#[cfg(test)]
mod tests {
    use config::{Config, File, FileFormat};

    use super::*;

    #[test]
    fn defaults_to_no_log_rotation() {
        let sot = DefaultSection::default();
        assert_eq!(sot.log_rotation_type, LogRotationType::None);
        assert_eq!(sot.log_rotate_interval, None);
        assert_eq!(sot.log_rotate_interval_type, LogRotateIntervalType::Days);
        assert_eq!(sot.max_logfile_count, None);
    }

    #[test]
    fn parses_log_rotation_options_from_ini() {
        let c = Config::builder()
            .add_source(File::from_str(
                "log_rotation_type = interval\n\
                 log_rotate_interval = 1\n\
                 log_rotate_interval_type = hours\n\
                 max_logfile_count = 7",
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let sot: DefaultSection = c.try_deserialize().unwrap();
        assert_eq!(sot.log_rotation_type, LogRotationType::Interval);
        assert_eq!(sot.log_rotate_interval, Some(1));
        assert_eq!(sot.log_rotate_interval_type, LogRotateIntervalType::Hours);
        assert_eq!(sot.max_logfile_count, Some(7));
    }

    #[test]
    fn rejects_unsupported_size_rotation_type() {
        let c = Config::builder()
            .add_source(File::from_str("log_rotation_type = size", FileFormat::Ini))
            .build()
            .unwrap();
        assert!(c.try_deserialize::<DefaultSection>().is_err());
    }
}
