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

use std::path::PathBuf;

use serde::Deserialize;

use crate::common::{csv, option_u32_from_str_or_int};

/// Server listener configuration.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ListenerConfig {
    Spiffe(SpiffeListener),
    #[default]
    Http,
    UnixSocket(UnixSocketListener),
}

/// Server listener with SPIFFE mTLS support.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct SpiffeListener {
    /// Trusted domains to accept SPIFFE certificates from clients.
    #[serde(deserialize_with = "csv")]
    pub trust_domains: Vec<String>,
}

/// Server listener listening on the Unix socket.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct UnixSocketListener {
    /// Socket path. Defaults to `/var/lib/keystone/keystone.sock`.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    /// Trusted domains to accept SPIFFE certificates from clients.
    #[serde(deserialize_with = "csv")]
    pub trust_domains: Vec<String>,

    /// If set, reject connections from clients whose UID does not match this value.
    #[serde(deserialize_with = "option_u32_from_str_or_int", default)]
    pub peer_uid: Option<u32>,

    /// If set, reject connections from clients whose GID does not match this value.
    #[serde(deserialize_with = "option_u32_from_str_or_int", default)]
    pub peer_gid: Option<u32>,
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/var/lib/keystone/keystone.sock")
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
trust_domains = "example.com"
"#,
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let sot: ListenerConfig = c.try_deserialize().unwrap();
        if let ListenerConfig::Spiffe(s) = sot {
            assert!(s.trust_domains.contains(&"example.com".to_string()));
        } else {
            panic!("should be spiffe listener");
        }
    }

    #[test]
    fn test_unix_socket_peer_creds() {
        let c = Config::builder()
            .add_source(File::from_str(
                r#"
type = "unixsocket"
trust_domains = "example.com"
peer_uid = 42
peer_gid = 100
"#,
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let sot: ListenerConfig = c.try_deserialize().unwrap();
        if let ListenerConfig::UnixSocket(us) = sot {
            assert!(us.trust_domains.contains(&"example.com".to_string()));
            assert_eq!(us.peer_uid, Some(42));
            assert_eq!(us.peer_gid, Some(100));
        } else {
            panic!("should be UnixSocket listener");
        }
        let c = Config::builder()
            .add_source(File::from_str(
                r#"
type = "unixsocket"
trust_domains = "example.com"
peer_uid = 42
peer_gid = 100
"#,
                FileFormat::Toml,
            ))
            .build()
            .unwrap();
        let sot: ListenerConfig = c.try_deserialize().unwrap();
        if let ListenerConfig::UnixSocket(us) = sot {
            assert!(us.trust_domains.contains(&"example.com".to_string()));
            assert_eq!(us.peer_uid, Some(42));
            assert_eq!(us.peer_gid, Some(100));
        } else {
            panic!("should be UnixSocket listener");
        }
    }

    #[test]
    fn test_unix_socket_peer_creds_defaults() {
        let c = Config::builder()
            .add_source(File::from_str(
                r#"
type = "unixsocket"
trust_domains = "example.com"
"#,
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let sot: ListenerConfig = c.try_deserialize().unwrap();
        if let ListenerConfig::UnixSocket(us) = sot {
            assert!(us.trust_domains.contains(&"example.com".to_string()));
            assert_eq!(us.peer_uid, None);
            assert_eq!(us.peer_gid, None);
        } else {
            panic!("should be UnixSocket listener");
        }
    }
}
