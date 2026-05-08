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
//! # Server listeners

use serde::Deserialize;

use crate::common::csv;

/// Server listener configuration.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ListenerConfig {
    Spiffe(SpiffeListener),
    #[default]
    Http,
}

/// Server listener with SPIFFE mTLS support.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct SpiffeListener {
    /// Trusted domains to accept SPIFFE certificates from clients.
    #[serde(deserialize_with = "csv")]
    pub trust_domains: Vec<String>,
}

#[cfg(test)]
mod tests {
    use config::{Config, File, FileFormat};

    use super::*;

    #[test]
    fn test_deser_ini() {
        let c = Config::builder()
            .add_source(File::from_str(
                r#"
type = "http"
"#,
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let sot: ListenerConfig = c.try_deserialize().unwrap();
        if let ListenerConfig::Http = sot {
        } else {
            panic!("should be Http listener");
        }
        let c = Config::builder()
            .add_source(File::from_str(
                r#"
type = spiffe
trust_domains = "a,b,c"
"#,
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let sot: ListenerConfig = c.try_deserialize().unwrap();
        if let ListenerConfig::Spiffe(s) = sot {
            assert!(s.trust_domains.contains(&String::from("a")));
        } else {
            panic!("should be spiffe listener");
        }
        let c = Config::builder()
            .add_source(File::from_str(
                r#"
type = spiffe
trust_domains = ""
"#,
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let sot: ListenerConfig = c.try_deserialize().unwrap();
        if let ListenerConfig::Spiffe(s) = sot {
            assert!(
                s.trust_domains.is_empty(),
                "must be empty, instead is {:?}",
                s.trust_domains
            );
        } else {
            panic!("should be spiffe listener");
        }
    }
}
