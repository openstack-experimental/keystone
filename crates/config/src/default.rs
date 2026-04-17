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

    /// Log output to standard error.
    #[serde(default)]
    pub use_stderr: bool,
}
