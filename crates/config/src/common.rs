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
//! # Keystone configuration
//!
//! Parsing of the Keystone configuration file implementation.
use std::path::PathBuf;

use chrono::TimeDelta;
use derive_builder::Builder;
use eyre::{Context, Report};
use ipnet::IpNet;
use secrecy::SecretSlice;
use serde::{Deserialize, Deserializer};

pub fn csv<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(String::deserialize(deserializer)?
        .split(',')
        .filter(|res| !res.is_empty())
        .map(Into::into)
        .collect())
}

/// Deserialize a comma-separated list of CIDR blocks directly into parsed
/// [`IpNet`] networks. Like [`csv`], but each entry is parsed into its target
/// type at configuration-load time rather than on every request, so the hot
/// path only borrows an already-parsed `&[IpNet]`. A malformed CIDR fails
/// configuration loading up front instead of being silently ignored later.
pub fn csv_ipnet<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer)?
        .split(',')
        .map(str::trim)
        .filter(|res| !res.is_empty())
        .map(|cidr| {
            cidr.parse::<IpNet>().map_err(|error| {
                serde::de::Error::custom(format!("invalid CIDR {cidr:?}: {error}"))
            })
        })
        .collect()
}

/// Forwarding header an operator asserts its trusted proxies sanitize.
///
/// Exactly one header is selected for each ingress trust boundary. Trusting
/// both implicitly would allow a proxy that only owns `X-Forwarded-For` to
/// pass through a client-forged RFC 7239 `Forwarded` header (or vice versa).
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyHeader {
    /// The de-facto standard header used by the existing ingress paths.
    #[default]
    XForwardedFor,
    /// RFC 7239 `Forwarded`; opt in only when every trusted proxy sanitizes it.
    Forwarded,
}

impl ProxyHeader {
    /// Lowercase HTTP field name used by `HeaderMap` and normalized maps.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XForwardedFor => "x-forwarded-for",
            Self::Forwarded => "forwarded",
        }
    }
}

// /// Deserializes an i64 and interprets it as total SECONDS for
// /// chrono::TimeDelta.
// fn timedelta_from_seconds<'de, D>(deserializer: D) -> Result<TimeDelta,
// D::Error> where
//     D: Deserializer<'de>,
// {
//     // Read the input number from JSON as an i64
//     let seconds = i64::deserialize(deserializer)?;
//
//     // Convert the number into a TimeDelta representing seconds
//     TimeDelta::try_seconds(seconds)
//         .ok_or_else(|| serde::de::Error::custom("TimeDelta overflow for
// seconds")) }

/// Deserializes an `Option<i64>` and interprets `Some(i64)` as total SECONDS
/// for TimeDelta.
pub fn optional_timedelta_from_seconds<'de, D>(
    deserializer: D,
) -> Result<Option<TimeDelta>, D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize the field content into Option<i64>.
    // Serde handles 'null' or an absent field by returning None here.
    let seconds_opt: Option<i64> = Option::deserialize(deserializer)?;

    match seconds_opt {
        // If a number was present, convert it to TimeDelta and wrap it in Some.
        Some(seconds) => TimeDelta::try_seconds(seconds)
            .map(Some) // Map TimeDelta to Some(TimeDelta)
            .ok_or_else(|| serde::de::Error::custom("TimeDelta overflow for optional seconds")),

        // If None was present (null or missing field), return Ok(None).
        None => Ok(None),
    }
}

pub fn default_sql_driver() -> String {
    "sql".into()
}

pub fn default_raft_driver() -> String {
    "raft".into()
}

pub fn default_true() -> bool {
    true
}

/// Deserialize `Option<u32>` from either a string or an integer value.
/// This handles both INI format (all values are strings) and TOML/JSON format
/// (integers are passed as-is).
pub fn option_u32_from_str_or_int<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_option(OptionU32Visitor)
}

struct OptionU32Visitor;

impl<'de> serde::de::Visitor<'de> for OptionU32Visitor {
    type Value = Option<u32>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("an optional u32, either as a string or integer")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(U32StrOrIntVisitor).map(Some)
    }
}

struct U32StrOrIntVisitor;

impl<'de> serde::de::Visitor<'de> for U32StrOrIntVisitor {
    type Value = u32;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a u32 as string or integer, optionally 0x-prefixed hex")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
            u32::from_str_radix(hex, 16).map_err(E::custom)
        } else {
            v.parse().map_err(E::custom)
        }
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        u32::try_from(v).map_err(|_| E::custom(format!("value {} out of range for u32", v)))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        u32::try_from(v).map_err(|_| E::custom(format!("value {} out of range for u32", v)))
    }
}

/// mTLS configuration for the server Listener cluster.
#[derive(Builder, Clone, Debug, Default, Deserialize)]
#[builder(setter(strip_option, into))]
pub struct TlsConfiguration {
    /// The CA certificate content to validate connections from clients or
    /// peers.
    #[builder(default)]
    #[serde(skip)]
    pub tls_client_ca_content: Option<SecretSlice<u8>>,

    /// Path to the CA certificate to validate connections from clients or
    /// peers.
    #[builder(default)]
    #[serde(default)]
    pub(crate) tls_client_ca_file: Option<PathBuf>,

    /// The TLS client certificate file content.
    #[builder(default)]
    #[serde(skip)]
    pub tls_cert_content: Option<SecretSlice<u8>>,

    /// Path to the TLS client certificate file.
    #[builder(default)]
    #[serde(default)]
    pub(crate) tls_cert_file: Option<PathBuf>,

    /// The TLS certificate key file content.
    #[builder(default)]
    #[serde(skip)]
    pub tls_key_content: Option<SecretSlice<u8>>,

    /// Path to the TLS certificate key file.
    #[builder(default)]
    #[serde(default)]
    pub(crate) tls_key_file: Option<PathBuf>,
}

impl TlsConfiguration {
    pub fn read_certs(&mut self) -> Result<(), Report> {
        if let Some(crt) = &self.tls_cert_file {
            self.tls_cert_content = Some(
                std::fs::read(crt)
                    .wrap_err_with(|| format!("reading tls cert file {:?}", self.tls_cert_file))?
                    .into(),
            );
        }
        if let Some(key) = &self.tls_key_file {
            self.tls_key_content = Some(
                std::fs::read(key)
                    .wrap_err_with(|| format!("reading tls key file {:?}", self.tls_key_file))?
                    .into(),
            );
        }
        if let Some(ca) = &self.tls_client_ca_file {
            self.tls_client_ca_content = Some(
                std::fs::read(ca)
                    .wrap_err_with(|| format!("reading tls ca file {:?}", ca))?
                    .into(),
            );
        }
        Ok(())
    }
}

/// Server interface type.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub enum Interface {
    Admin,
    Internal,
    Public,
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use config::{Config, File, FileFormat};
    use secrecy::ExposeSecret;
    use tempfile::NamedTempFile;

    use super::*;

    #[tokio::test]
    async fn test_read() {
        let mut ca_file = NamedTempFile::new().unwrap();
        write!(ca_file, "ca").unwrap();
        let mut cert_file = NamedTempFile::new().unwrap();
        write!(cert_file, "cert").unwrap();
        let mut key_file = NamedTempFile::new().unwrap();
        write!(key_file, "key").unwrap();
        let c = Config::builder()
            .add_source(File::from_str(
                format!(
                    r#"
cluster_addr = https://localhost:8310
node_id = 1
path = /keystone/storage
tls_key_file = {:?}
tls_cert_file = {:?}
tls_client_ca_file = {:?}
"#,
                    key_file.path(),
                    cert_file.path(),
                    ca_file.path()
                )
                .as_str(),
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let mut cfg: TlsConfiguration = c.try_deserialize().unwrap();
        cfg.read_certs().unwrap();
        assert!(
            cfg.tls_client_ca_content
                .is_some_and(|x| x.expose_secret() == "ca".as_bytes()),
        );
        assert!(
            cfg.tls_cert_content
                .is_some_and(|x| x.expose_secret() == "cert".as_bytes()),
        );
        assert!(
            cfg.tls_key_content
                .is_some_and(|x| x.expose_secret() == "key".as_bytes()),
        );
    }
}
