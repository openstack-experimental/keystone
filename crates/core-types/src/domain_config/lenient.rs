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

//! # oslo.config compatible decoding of stored values
//!
//! Domain configuration values reach us from two sources with different
//! fidelity: the REST API, where a client sends real JSON types, and a
//! `keystone.<domain>.conf` file, where every value is a string.
//! python-keystone hands both to oslo.config, which coerces the string form
//! (`"True"`, `"10"`, `"a,b"`) into the type the option was declared with.
//!
//! [`from_value`] reproduces that coercion while decoding into the ordinary
//! config structs of [`openstack_keystone_config`], so a `use_tls` written as
//! `true` and one written as `"True"` decode identically without either
//! struct having to declare anything about it. It is a [`Deserializer`]
//! adaptor rather than a set of field attributes precisely so that it stays
//! independent of the struct it decodes into: an option added to
//! `LdapProvider` is covered by it the day it is added.

use std::fmt;

use serde::de::value::StringDeserializer;
use serde::de::{
    self, DeserializeOwned, DeserializeSeed, Deserializer, IntoDeserializer, MapAccess, SeqAccess,
    Visitor,
};
use serde_json::{Map, Value};

/// Decode a JSON value into `T`, coercing scalars the way oslo.config does.
///
/// # Parameters
/// - `value`: The raw value, as stored or as sent by a client.
///
/// # Returns
/// - `Result<T, serde_json::Error>` - The decoded value, or an error naming
///   what was expected and what arrived.
pub fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, serde_json::Error> {
    T::deserialize(LenientValue(value))
}

/// A JSON value that decodes leniently; see [`from_value`].
struct LenientValue(Value);

/// Describe a value that cannot be coerced to what the target asked for.
///
/// # Parameters
/// - `expected`: What the option can hold.
/// - `value`: The value that arrived.
///
/// # Returns
/// - `serde_json::Error` - The error to report.
fn mismatch(expected: &str, value: &Value) -> serde_json::Error {
    de::Error::custom(format!("expected {expected}, got `{value}`"))
}

/// Coerce a value to a boolean the way oslo.config's `BoolOpt` reads it.
///
/// Integers are accepted as `0`/`1` because that is what a `BoolOpt` becomes
/// once the stored JSON reaches python code.
///
/// # Parameters
/// - `value`: The raw value.
///
/// # Returns
/// - `Result<bool, serde_json::Error>` - The flag, or a mismatch error.
fn coerce_bool(value: &Value) -> Result<bool, serde_json::Error> {
    match value {
        Value::Bool(flag) => Ok(*flag),
        Value::Number(number) => match number.as_i64() {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err(mismatch("a boolean", value)),
        },
        Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
            "true" | "t" | "yes" | "y" | "on" | "1" => Ok(true),
            "false" | "f" | "no" | "n" | "off" | "0" => Ok(false),
            _ => Err(mismatch("a boolean", value)),
        },
        _ => Err(mismatch("a boolean", value)),
    }
}

/// Coerce a value to a signed integer.
///
/// # Parameters
/// - `value`: The raw value.
///
/// # Returns
/// - `Result<i64, serde_json::Error>` - The integer, or a mismatch error.
fn coerce_i64(value: &Value) -> Result<i64, serde_json::Error> {
    match value {
        Value::Number(number) => number.as_i64().ok_or_else(|| mismatch("an integer", value)),
        Value::String(text) => text
            .trim()
            .parse()
            .map_err(|_| mismatch("an integer", value)),
        _ => Err(mismatch("an integer", value)),
    }
}

/// Coerce a value to an unsigned integer.
///
/// # Parameters
/// - `value`: The raw value.
///
/// # Returns
/// - `Result<u64, serde_json::Error>` - The integer, or a mismatch error.
fn coerce_u64(value: &Value) -> Result<u64, serde_json::Error> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| mismatch("a positive integer", value)),
        Value::String(text) => text
            .trim()
            .parse()
            .map_err(|_| mismatch("a positive integer", value)),
        _ => Err(mismatch("a positive integer", value)),
    }
}

/// Coerce a value to a floating point number.
///
/// # Parameters
/// - `value`: The raw value.
///
/// # Returns
/// - `Result<f64, serde_json::Error>` - The number, or a mismatch error.
fn coerce_f64(value: &Value) -> Result<f64, serde_json::Error> {
    match value {
        Value::Number(number) => number.as_f64().ok_or_else(|| mismatch("a number", value)),
        Value::String(text) => text.trim().parse().map_err(|_| mismatch("a number", value)),
        _ => Err(mismatch("a number", value)),
    }
}

/// Coerce a value to a string.
///
/// A scalar is rendered the way python's `str()` renders it, which is what a
/// `StrOpt` given a JSON boolean or number ends up holding.
///
/// # Parameters
/// - `value`: The raw value.
///
/// # Returns
/// - `Result<String, serde_json::Error>` - The text, or a mismatch error.
fn coerce_string(value: &Value) -> Result<String, serde_json::Error> {
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Bool(true) => Ok("True".to_string()),
        Value::Bool(false) => Ok("False".to_string()),
        Value::Number(number) => Ok(number.to_string()),
        _ => Err(mismatch("a string", value)),
    }
}

/// Coerce a value to a list the way oslo.config's `ListOpt` reads it.
///
/// # Parameters
/// - `value`: The raw value; a JSON array, or the comma separated spelling.
///
/// # Returns
/// - `Result<Vec<Value>, serde_json::Error>` - The entries, with surrounding
///   whitespace removed and empty ones dropped, or a mismatch error.
fn coerce_seq(value: Value) -> Result<Vec<Value>, serde_json::Error> {
    match value {
        Value::Array(entries) => Ok(entries),
        Value::String(ref text) => Ok(text
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| Value::String(entry.to_string()))
            .collect()),
        ref other => Err(mismatch("a list", other)),
    }
}

impl<'de> Deserializer<'de> for LenientValue {
    type Error = serde_json::Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            Value::Null => visitor.visit_unit(),
            Value::Bool(flag) => visitor.visit_bool(flag),
            Value::String(text) => visitor.visit_string(text),
            Value::Array(entries) => visitor.visit_seq(SeqAdaptor::new(entries)),
            Value::Object(map) => visitor.visit_map(MapAdaptor::new(map)),
            // Numbers carry a width of their own; serde_json already picks the
            // right `visit_*` for them.
            number => number.deserialize_any(visitor),
        }
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_bool(coerce_bool(&self.0)?)
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_i64(coerce_i64(&self.0)?)
    }

    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_i64(coerce_i64(&self.0)?)
    }

    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_i64(coerce_i64(&self.0)?)
    }

    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_i64(coerce_i64(&self.0)?)
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_u64(coerce_u64(&self.0)?)
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_u64(coerce_u64(&self.0)?)
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_u64(coerce_u64(&self.0)?)
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_u64(coerce_u64(&self.0)?)
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_f64(coerce_f64(&self.0)?)
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_f64(coerce_f64(&self.0)?)
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_string(coerce_string(&self.0)?)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_any(visitor)
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_any(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            Value::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_seq(SeqAdaptor::new(coerce_seq(self.0)?))
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            Value::Object(map) => visitor.visit_map(MapAdaptor::new(map)),
            ref other => Err(mismatch("a mapping", other)),
        }
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        match self.0 {
            // The config enums are unit-only (`tls_req_cert = never`), which
            // is the only spelling a config file can deliver.
            Value::String(text) => {
                let variant: StringDeserializer<Self::Error> = text.into_deserializer();
                visitor.visit_enum(variant)
            }
            other => other.deserialize_enum(name, variants, visitor),
        }
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_unit()
    }
}

/// Sequence access that keeps its entries lenient.
struct SeqAdaptor {
    /// The remaining entries.
    entries: std::vec::IntoIter<Value>,
}

impl SeqAdaptor {
    /// Wrap the entries of an array.
    ///
    /// # Parameters
    /// - `entries`: The array entries.
    ///
    /// # Returns
    /// - `Self` - The access.
    fn new(entries: Vec<Value>) -> Self {
        Self {
            entries: entries.into_iter(),
        }
    }
}

impl<'de> SeqAccess<'de> for SeqAdaptor {
    type Error = serde_json::Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        match self.entries.next() {
            Some(entry) => seed.deserialize(LenientValue(entry)).map(Some),
            None => Ok(None),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.entries.len())
    }
}

/// Map access that keeps its values lenient.
struct MapAdaptor {
    /// The remaining entries.
    entries: serde_json::map::IntoIter,
    /// The value of the entry whose key was just handed out.
    value: Option<Value>,
}

impl MapAdaptor {
    /// Wrap the entries of an object.
    ///
    /// # Parameters
    /// - `map`: The object.
    ///
    /// # Returns
    /// - `Self` - The access.
    fn new(map: Map<String, Value>) -> Self {
        Self {
            entries: map.into_iter(),
            value: None,
        }
    }
}

impl<'de> MapAccess<'de> for MapAdaptor {
    type Error = serde_json::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        match self.entries.next() {
            Some((key, value)) => {
                self.value = Some(value);
                let key: StringDeserializer<Self::Error> = key.into_deserializer();
                seed.deserialize(key).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        // `next_key_seed` always sets the value first; the fallback only keeps
        // a misbehaving visitor from panicking.
        seed.deserialize(LenientValue(self.value.take().unwrap_or(Value::Null)))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.entries.len())
    }
}

impl fmt::Debug for LenientValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LenientValue").field(&self.0).finish()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use openstack_keystone_config::{
        AliasDereferencing, IdentityProvider, LdapProvider, QueryScope, TlsReqCert,
    };
    use secrecy::ExposeSecret;
    use serde_json::json;

    use super::*;

    #[test]
    fn decodes_real_json_types() {
        let ldap: LdapProvider = from_value(json!({
            "url": "ldaps://directory.example.com",
            "use_tls": true,
            "page_size": 100,
            "pool_retry_delay": 0.5,
            "user_attribute_ignore": ["mail", "enabled"],
        }))
        .unwrap();
        assert_eq!(ldap.url, "ldaps://directory.example.com");
        assert!(ldap.use_tls);
        assert_eq!(ldap.page_size, 100);
        assert!((ldap.pool_retry_delay - 0.5).abs() < f64::EPSILON);
        assert_eq!(
            ldap.user_attribute_ignore,
            HashSet::from(["mail".to_string(), "enabled".to_string()])
        );
    }

    #[test]
    fn decodes_the_config_file_spelling_of_every_scalar() {
        let ldap: LdapProvider = from_value(json!({
            "use_tls": "True",
            "use_pool": "0",
            "page_size": "100",
            "pool_retry_delay": "0.5",
            "user_attribute_ignore": "mail, enabled ,",
            "tls_req_cert": "never",
            "query_scope": "sub",
            "alias_dereferencing": "always",
        }))
        .unwrap();
        assert!(ldap.use_tls);
        assert!(!ldap.pool);
        assert_eq!(ldap.page_size, 100);
        assert!((ldap.pool_retry_delay - 0.5).abs() < f64::EPSILON);
        assert_eq!(
            ldap.user_attribute_ignore,
            HashSet::from(["mail".to_string(), "enabled".to_string()])
        );
        assert_eq!(ldap.tls_req_cert, TlsReqCert::Never);
        assert_eq!(ldap.query_scope, QueryScope::Sub);
        assert_eq!(ldap.alias_dereferencing, AliasDereferencing::Always);
    }

    #[test]
    fn accepts_integers_for_booleans() {
        let ldap: LdapProvider = from_value(json!({"use_tls": 1, "use_pool": 0})).unwrap();
        assert!(ldap.use_tls);
        assert!(!ldap.pool);
    }

    #[test]
    fn decodes_both_spellings_of_an_attribute_mapping() {
        for value in [
            json!({"user_additional_attribute_mapping": ["mail:email"]}),
            json!({"user_additional_attribute_mapping": "mail:email"}),
            json!({"user_additional_attribute_mapping": {"mail": "email"}}),
        ] {
            let ldap: LdapProvider = from_value(value.clone()).unwrap();
            assert_eq!(
                ldap.user_additional_attribute_mapping,
                HashMap::from([("mail".to_string(), "email".to_string())]),
                "{value}"
            );
        }
    }

    #[test]
    fn decodes_a_secret_option() {
        let ldap: LdapProvider = from_value(json!({"password": "s3cr3t"})).unwrap();
        assert_eq!(
            ldap.password
                .map(|password| password.expose_secret().to_string()),
            Some("s3cr3t".to_string())
        );
    }

    #[test]
    fn keeps_a_string_option_a_string() {
        // `user_enabled_default` doubles as a boolean and as an integer
        // literal, so it must stay whatever the client wrote.
        let ldap: LdapProvider = from_value(json!({"user_enabled_default": "512"})).unwrap();
        assert_eq!(ldap.user_enabled_default, "512");
        let ldap: LdapProvider = from_value(json!({"user_enabled_default": true})).unwrap();
        assert_eq!(ldap.user_enabled_default, "True");
    }

    #[test]
    fn decodes_both_spellings_of_a_list_limit() {
        let identity: IdentityProvider = from_value(json!({"list_limit": 100})).unwrap();
        assert_eq!(identity.list_limit.list_limit, Some(100));
        let identity: IdentityProvider = from_value(json!({"list_limit": "100"})).unwrap();
        assert_eq!(identity.list_limit.list_limit, Some(100));
        let identity: IdentityProvider =
            from_value(json!({"list_limit": {"list_limit": 5, "max_list_limit": 50}})).unwrap();
        assert_eq!(identity.list_limit.list_limit, Some(5));
        assert_eq!(identity.list_limit.max_list_limit, Some(50));
    }

    #[test]
    fn reports_what_it_expected() {
        let err = from_value::<LdapProvider>(json!({"page_size": "ten"})).unwrap_err();
        assert_eq!(err.to_string(), "expected an integer, got `\"ten\"`");
        let err = from_value::<LdapProvider>(json!({"use_tls": "maybe"})).unwrap_err();
        assert_eq!(err.to_string(), "expected a boolean, got `\"maybe\"`");
        let err = from_value::<LdapProvider>(json!({"pool_retry_delay": "later"})).unwrap_err();
        assert_eq!(err.to_string(), "expected a number, got `\"later\"`");
        let err = from_value::<LdapProvider>(json!({"url": ["a"]})).unwrap_err();
        assert_eq!(err.to_string(), "expected a string, got `[\"a\"]`");
    }

    #[test]
    fn leaves_unknown_options_alone() {
        // The whitelist is what rejects an unsupported option; decoding must
        // not fail on a stored row it has no field for.
        let ldap: LdapProvider = from_value(json!({"bind_dn": "cn=admin"})).unwrap();
        assert_eq!(ldap.url, LdapProvider::default().url);
    }
}
