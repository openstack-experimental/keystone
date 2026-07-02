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
//! # EC2 tokens configuration (ADR 0019 §5)
use serde::Deserialize;

/// `POST /v3/ec2tokens` configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct Ec2Provider {
    /// Replay-prevention window (seconds) for the EC2 request timestamp
    /// (CVE-2020-12692). This is the Python Keystone default; it must not be
    /// confused with the 4-hour window that is only an AWS SigV2
    /// recommendation, not what Keystone implements.
    #[serde(default = "default_auth_ttl")]
    pub auth_ttl: i64,
}

fn default_auth_ttl() -> i64 {
    300
}

impl Default for Ec2Provider {
    fn default() -> Self {
        Self {
            auth_ttl: default_auth_ttl(),
        }
    }
}
