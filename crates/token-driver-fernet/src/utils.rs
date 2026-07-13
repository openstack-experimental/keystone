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
//! # Fernet utils
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rmp::{
    Marker,
    decode::{self, *},
    encode::{self, *},
};
use std::io::{self, Read};
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

use openstack_keystone_key_repository::{CachedKeyRepository, FilesystemKeySource, KeyRepository};

use crate::error::FernetDriverError;

/// How often the filesystem watcher's poll fallback checks for changes if
/// inotify doesn't fire — only relevant to [`FernetUtils::start_cached`],
/// the one long-lived, auto-refreshing view a [`crate::FernetTokenProvider`]
/// holds. The one-shot operations below (`initialize_key_repository`,
/// `rotate`, `check_startup_null_key`) don't watch at all.
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Fernet utils: a thin adapter over
/// [`openstack_keystone_key_repository`], which owns the actual key
/// parsing/rotation/Null-Key-detection logic shared with the credential
/// driver (ADR 0019 §4).
#[derive(Clone, Debug, Default)]
pub struct FernetUtils {
    pub key_repository: PathBuf,
    pub max_active_keys: usize,
}

impl FernetUtils {
    fn repo(&self) -> KeyRepository<FilesystemKeySource> {
        KeyRepository::new(
            FilesystemKeySource::new(self.key_repository.clone()),
            self.max_active_keys,
        )
    }

    /// `token_setup`: create the initial staged key. Idempotent-ish:
    /// overwrites the staged key if it already exists, matching the
    /// underlying atomic-write semantics.
    pub async fn initialize_key_repository(&self) -> Result<(), FernetDriverError> {
        self.repo().setup().await.map_err(Into::into)
    }

    /// Startup-time Null Key check (ADR 0019 §4, Security), mirroring the
    /// credential key repository's equivalent check.
    pub async fn check_startup_null_key(
        &self,
        insecure_allow_null_key: bool,
    ) -> Result<(), FernetDriverError> {
        self.repo()
            .check_startup_null_key(insecure_allow_null_key)
            .await
            .map_err(Into::into)
    }

    /// `token_rotate`: promote the staged key to primary, stage a fresh
    /// key, and prune beyond `max_active_keys`. Unlike the credential
    /// driver's rotate, there is no "still-encrypted-with-a-stale-key"
    /// safety check to run first — expired tokens simply fail to decrypt,
    /// they are never migrated.
    pub async fn rotate(&self) -> Result<(), FernetDriverError> {
        self.repo().rotate().await.map_err(Into::into)
    }

    /// Start a cached, auto-refreshing view of this key repository: the
    /// initial load happens here, and a background task keeps it fresh as
    /// keys are rotated on disk, so [`crate::FernetTokenProvider`] never
    /// touches the filesystem on the encrypt/decrypt hot path and never
    /// serves a stale key set after a rotation.
    pub async fn start_cached(
        &self,
        insecure_allow_null_key: bool,
    ) -> Result<CachedKeyRepository<FilesystemKeySource>, FernetDriverError> {
        let source = FilesystemKeySource::watched(self.key_repository.clone(), POLL_INTERVAL);
        let repo = KeyRepository::new(source, self.max_active_keys);
        CachedKeyRepository::start(repo, insecure_allow_null_key)
            .await
            .map_err(Into::into)
    }
}

/// Read the length that follows an already-consumed `Bin8`/`Bin16`/`Bin32`
/// marker.
///
/// MessagePack stores this length as a raw big-endian integer immediately
/// after the marker byte, not as another MessagePack-encoded value, so it
/// must not be decoded with a marker-aware reader such as `read_pfix`.
///
/// # Parameters
/// - `marker`: The already-consumed marker (`Bin8`, `Bin16` or `Bin32`).
/// - `rd`: The reader to read from.
///
/// # Returns
/// A `Result` containing the length if successful, or a `FernetDriverError`.
fn read_bin_len_for_marker<R: Read>(marker: Marker, rd: &mut R) -> Result<u32, FernetDriverError> {
    match marker {
        Marker::Bin8 => Ok(u32::from(byteorder::ReadBytesExt::read_u8(rd)?)),
        Marker::Bin16 => Ok(u32::from(byteorder::ReadBytesExt::read_u16::<
            byteorder::BigEndian,
        >(rd)?)),
        Marker::Bin32 => Ok(byteorder::ReadBytesExt::read_u32::<byteorder::BigEndian>(
            rd,
        )?),
        other => Err(FernetDriverError::InvalidTokenUuidMarker(other)),
    }
}

/// Read the length that follows an already-consumed `FixStr`/`Str8`/`Str16`/
/// `Str32` marker. See [`read_bin_len_for_marker`] for why this cannot be
/// decoded with a marker-aware reader.
///
/// # Parameters
/// - `marker`: The already-consumed marker.
/// - `rd`: The reader to read from.
///
/// # Returns
/// A `Result` containing the length if successful, or a `FernetDriverError`.
fn read_str_len_for_marker<R: Read>(marker: Marker, rd: &mut R) -> Result<u32, FernetDriverError> {
    match marker {
        Marker::FixStr(len) => Ok(len.into()),
        Marker::Str8 => Ok(u32::from(byteorder::ReadBytesExt::read_u8(rd)?)),
        Marker::Str16 => Ok(u32::from(byteorder::ReadBytesExt::read_u16::<
            byteorder::BigEndian,
        >(rd)?)),
        Marker::Str32 => Ok(byteorder::ReadBytesExt::read_u32::<byteorder::BigEndian>(
            rd,
        )?),
        other => Err(FernetDriverError::InvalidTokenUuidMarker(other)),
    }
}

/// Read the encoded authentication methods bitmask.
///
/// Values below 128 are encoded as a MessagePack positive fixint (the
/// historical, compact representation). Values using bit 7 (the 8th
/// configured auth method) no longer fit that format and are encoded as a
/// MessagePack `uint8` instead; both are accepted here.
///
/// # Parameters
/// - `rd`: The reader to read from.
///
/// # Returns
/// A `Result` containing the encoded byte if successful, or a
/// `FernetDriverError`.
pub fn read_auth_methods_code<R: Read>(rd: &mut R) -> Result<u8, FernetDriverError> {
    match read_marker(rd).map_err(ValueReadError::from)? {
        Marker::FixPos(val) => Ok(val),
        Marker::U8 => Ok(byteorder::ReadBytesExt::read_u8(rd)?),
        other => Err(FernetDriverError::InvalidTokenUuidMarker(other)),
    }
}

/// Write the encoded authentication methods bitmask.
///
/// Uses a positive fixint for values below 128 (compact, and compatible with
/// every token written so far), falling back to a `uint8` for values that
/// need the full byte range (`write_pfix` would panic on those).
///
/// # Parameters
/// - `wd`: The writer to write to.
/// - `code`: The encoded authentication methods byte.
///
/// # Returns
/// A `Result` indicating success or a `FernetDriverError`.
pub fn write_auth_methods_code<W: RmpWrite>(wd: &mut W, code: u8) -> Result<(), FernetDriverError> {
    if code < 128 {
        write_pfix(wd, code).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))
    } else {
        write_u8(wd, code).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))
    }
}

/// Read binary data from the payload.
///
/// # Parameters
/// - `len`: The length of the data to read.
/// - `rd`: The reader to read from.
///
/// # Returns
/// A `Result` containing the read bytes if successful, or an `io::Error`.
pub fn read_bin_data<R: Read>(len: u32, rd: &mut R) -> Result<Vec<u8>, io::Error> {
    let mut buf = Vec::with_capacity(len.min(1 << 16) as usize);
    let bytes_read = rd.take(u64::from(len)).read_to_end(&mut buf)?;
    if bytes_read != len as usize {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(buf)
}

/// Read string data.
///
/// # Parameters
/// - `len`: The length of the data to read.
/// - `rd`: The reader to read from.
///
/// # Returns
/// A `Result` containing the read string if successful, or an `io::Error`.
pub fn read_str_data<R: Read>(len: u32, rd: &mut R) -> Result<String, io::Error> {
    Ok(String::from_utf8_lossy(&read_bin_data(len, rd)?).into_owned())
}

/// Write string.
///
/// # Parameters
/// - `wd`: The writer to write to.
/// - `data`: The string data to write.
///
/// # Returns
/// A `Result` indicating success or a `FernetDriverError`.
pub fn write_str<W: RmpWrite>(wd: &mut W, data: &str) -> Result<(), FernetDriverError> {
    encode::write_str(wd, data).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
    Ok(())
}

/// Read bytes as string.
///
/// # Parameters
/// - `rd`: The reader to read from.
///
/// # Returns
/// A `Result` containing the read string if successful, or a
/// `FernetDriverError`.
pub fn read_str<R: Read>(rd: &mut R) -> Result<String, FernetDriverError> {
    match read_marker(rd).map_err(ValueReadError::from)? {
        marker @ (Marker::Bin8 | Marker::Bin16 | Marker::Bin32) => {
            let len = read_bin_len_for_marker(marker, rd)?;
            Ok(String::from_utf8_lossy(&read_bin_data(len, rd)?).to_string())
        }
        marker @ (Marker::FixStr(_) | Marker::Str8 | Marker::Str16 | Marker::Str32) => {
            let len = read_str_len_for_marker(marker, rd)?;
            Ok(read_str_data(len, rd)?)
        }
        other => Err(FernetDriverError::InvalidTokenUuidMarker(other)),
    }
}

/// Read the UUID from the payload.
///
/// It is represented as an Array[bool, bytes] where first bool indicates
/// whether following bytes are UUID or just bytes that should be treated as a
/// string (for cases where ID is not a valid UUID).
///
/// # Parameters
/// - `rd`: The reader to read from.
///
/// # Returns
/// A `Result` containing the UUID string if successful, or a
/// `FernetDriverError`.
pub fn read_uuid(rd: &mut &[u8]) -> Result<String, FernetDriverError> {
    match read_marker(rd).map_err(ValueReadError::from)? {
        Marker::FixArray(_) => {
            match read_marker(rd).map_err(ValueReadError::from)? {
                Marker::True => {
                    // This is uuid as bytes
                    // Technically we may fail reading it into bytes, but python part is
                    // responsible that it doesn not happen
                    let marker = read_marker(rd).map_err(ValueReadError::from)?;
                    if let Marker::Bin8 | Marker::Bin16 | Marker::Bin32 = marker {
                        let len = read_bin_len_for_marker(marker, rd)?;
                        return Ok(Uuid::try_from(read_bin_data(len, rd)?)?
                            .as_simple()
                            .to_string());
                    }
                }
                Marker::False => {
                    // This is not uuid
                    match read_marker(rd).map_err(ValueReadError::from)? {
                        marker @ (Marker::Bin8 | Marker::Bin16 | Marker::Bin32) => {
                            let len = read_bin_len_for_marker(marker, rd)?;
                            return Ok(
                                String::from_utf8_lossy(&read_bin_data(len, rd)?).to_string()
                            );
                        }
                        marker @ (Marker::FixStr(_)
                        | Marker::Str8
                        | Marker::Str16
                        | Marker::Str32) => {
                            let len = read_str_len_for_marker(marker, rd)?;
                            return Ok(read_str_data(len, rd)?);
                        }
                        other => {
                            return Err(FernetDriverError::InvalidTokenUuidMarker(other));
                        }
                    }
                }
                other => {
                    return Err(FernetDriverError::InvalidTokenUuidMarker(other));
                }
            }
        }
        Marker::FixStr(len) => {
            return Ok(read_str_data(len.into(), rd)?);
        }
        other => {
            return Err(FernetDriverError::InvalidTokenUuidMarker(other));
        }
    }
    Err(FernetDriverError::InvalidTokenUuid)
}

/// Write the UUID to the payload.
///
/// It is represented as an Array[bool, bytes] where first bool indicates
/// whether following bytes are UUID or just bytes that should be treated as a
/// string (for cases where ID is not a valid UUID).
///
/// # Parameters
/// - `wd`: The writer to write to.
/// - `uid`: The UUID string to write.
///
/// # Returns
/// A `Result` indicating success or a `FernetDriverError`.
pub fn write_uuid<W: RmpWrite>(wd: &mut W, uid: &str) -> Result<(), FernetDriverError> {
    match Uuid::parse_str(uid) {
        Ok(uuid) => {
            write_array_len(wd, 2).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
            write_bool(wd, true).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
            write_bin(wd, uuid.as_bytes())
                .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
        }
        _ => {
            write_array_len(wd, 2).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
            write_bool(wd, false).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
            write_bin(wd, uid.as_bytes())
                .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
        }
    }
    Ok(())
}

/// Read the time represented as a f64 of the UTC seconds.
///
/// # Parameters
/// - `rd`: The reader to read from.
///
/// # Returns
/// A `Result` containing the `DateTime<Utc>` if successful, or a
/// `FernetDriverError`.
pub fn read_time(rd: &mut &[u8]) -> Result<DateTime<Utc>, FernetDriverError> {
    DateTime::from_timestamp(read_f64(rd)?.round() as i64, 0).ok_or(FernetDriverError::InvalidToken)
}

/// Write the time represented as a f64 of the UTC seconds.
///
/// # Parameters
/// - `wd`: The writer to write to.
/// - `time`: The time to write.
///
/// # Returns
/// A `Result` indicating success or a `FernetDriverError`.
pub fn write_time<W: RmpWrite>(wd: &mut W, time: DateTime<Utc>) -> Result<(), FernetDriverError> {
    write_f64(wd, time.timestamp() as f64)
        .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
    Ok(())
}

/// Decode array of audit ids from the payload.
///
/// # Parameters
/// - `rd`: The reader to read from.
///
/// # Returns
/// A `Result` containing an iterator of audit IDs if successful, or a
/// `FernetDriverError`.
pub fn read_audit_ids(
    rd: &mut &[u8],
) -> Result<impl IntoIterator<Item = String> + use<>, FernetDriverError> {
    if let Marker::FixArray(len) = read_marker(rd).map_err(ValueReadError::from)? {
        let mut result: Vec<String> = Vec::new();
        for _ in 0..len {
            let marker = read_marker(rd).map_err(ValueReadError::from)?;
            if let Marker::Bin8 | Marker::Bin16 | Marker::Bin32 = marker {
                let bin_len = read_bin_len_for_marker(marker, rd)?;
                let dt = read_bin_data(bin_len, rd)?;
                let audit_id: String = URL_SAFE_NO_PAD.encode(dt);
                result.push(audit_id);
            } else {
                return Err(FernetDriverError::InvalidToken);
            }
        }
        return Ok(result.into_iter());
    }
    Err(FernetDriverError::InvalidToken)
}

/// Encode array of audit ids into the payload.
///
/// # Parameters
/// - `wd`: The writer to write to.
/// - `data`: The audit IDs to write.
///
/// # Returns
/// A `Result` indicating success or a `FernetDriverError`.
pub fn write_audit_ids<W: RmpWrite, I: IntoIterator<Item = String>>(
    wd: &mut W,
    data: I,
) -> Result<(), FernetDriverError> {
    let vals = Vec::from_iter(data);
    write_array_len(wd, vals.len() as u32)
        .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
    for val in vals.iter() {
        write_bin(
            wd,
            &URL_SAFE_NO_PAD
                .decode(val)
                .map_err(|_| FernetDriverError::AuditIdWrongFormat)?,
        )
        .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
    }
    Ok(())
}

/// Decode array of strings ids from the payload.
///
/// # Parameters
/// - `rd`: The reader to read from.
///
/// # Returns
/// A `Result` containing an iterator of UUID strings if successful, or a
/// `FernetDriverError`.
pub fn read_list_of_uuids(
    rd: &mut &[u8],
) -> Result<impl IntoIterator<Item = String> + use<>, FernetDriverError> {
    if let Marker::FixArray(len) = read_marker(rd).map_err(ValueReadError::from)? {
        let mut result: Vec<String> = Vec::new();
        for _ in 0..len {
            result.push(read_uuid(rd)?);
        }
        return Ok(result.into_iter());
    }
    Err(FernetDriverError::InvalidToken)
}

/// Encode array of bytes into the payload.
///
/// # Parameters
/// - `wd`: The writer to write to.
/// - `data`: The UUIDs to write.
///
/// # Returns
/// A `Result` indicating success or a `FernetDriverError`.
pub fn write_list_of_uuids<W: RmpWrite, I: IntoIterator<Item = V>, V: AsRef<str>>(
    wd: &mut W,
    data: I,
) -> Result<(), FernetDriverError> {
    let vals = Vec::from_iter(data);
    write_array_len(wd, vals.len() as u32)
        .map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
    for val in vals.iter() {
        write_uuid(wd, val.as_ref())?;
    }
    Ok(())
}

/// Read boolean.
///
/// # Parameters
/// - `rd`: The reader to read from.
///
/// # Returns
/// A `Result` containing the boolean value if successful, or a
/// `FernetDriverError`.
pub fn read_bool<R: Read>(rd: &mut R) -> Result<bool, FernetDriverError> {
    Ok(decode::read_bool(rd)?)
}

/// Write boolean.
///
/// # Parameters
/// - `wd`: The writer to write to.
/// - `data`: The boolean value to write.
///
/// # Returns
/// A `Result` indicating success or a `FernetDriverError`.
pub fn write_bool<W: RmpWrite>(wd: &mut W, data: bool) -> Result<(), FernetDriverError> {
    encode::write_bool(wd, data).map_err(|x| FernetDriverError::RmpEncode(x.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::FernetUtils;
    use chrono::{Local, SubsecRound};
    use tempfile::tempdir;

    use super::*;

    // Low-level key parsing/rotation/Null-Key-detection coverage lives with
    // `openstack-keystone-key-repository`, which this adapter delegates to.
    // These tests only cover the adapter wiring itself.

    #[tokio::test]
    async fn test_initialize_and_rotate_roundtrip() {
        let tmp_dir = tempdir().unwrap();
        let utils = FernetUtils {
            key_repository: tmp_dir.path().to_path_buf(),
            max_active_keys: 3,
        };
        utils.initialize_key_repository().await.unwrap();
        assert!(tmp_dir.path().join("0").exists());

        utils.rotate().await.unwrap();
        assert!(tmp_dir.path().join("1").exists(), "staged key promoted");
        assert!(tmp_dir.path().join("0").exists(), "fresh key staged");
    }

    #[tokio::test]
    async fn test_check_startup_null_key_refuses_by_default() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE;

        let tmp_dir = tempdir().unwrap();
        let utils = FernetUtils {
            key_repository: tmp_dir.path().to_path_buf(),
            max_active_keys: 3,
        };
        let null_key = URL_SAFE.encode([0u8; 32]);
        std::fs::write(tmp_dir.path().join("0"), null_key).unwrap();

        assert!(matches!(
            utils.check_startup_null_key(false).await,
            Err(FernetDriverError::NullKeyDetected)
        ));
        assert!(utils.check_startup_null_key(true).await.is_ok());
    }

    #[tokio::test]
    async fn test_start_cached_encrypts_and_decrypts() {
        let tmp_dir = tempdir().unwrap();
        let utils = FernetUtils {
            key_repository: tmp_dir.path().to_path_buf(),
            max_active_keys: 3,
        };
        utils.initialize_key_repository().await.unwrap();

        let cached = utils.start_cached(false).await.unwrap();
        let token = cached.current().multi_fernet.encrypt(b"payload");
        assert_eq!(
            cached.current().multi_fernet.decrypt(&token).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn test_write_read_uuid_str() {
        let mut buf = Vec::with_capacity(36);
        let uuid = "abc";
        write_uuid(&mut buf, uuid).unwrap();
        let msg = buf.clone();
        let mut decode_data = msg.as_slice();
        let decoded = read_uuid(&mut decode_data).unwrap();
        assert_eq!(uuid, decoded);
    }

    #[test]
    fn test_write_read_uuid() {
        let mut buf = Vec::with_capacity(36);
        let test = Uuid::new_v4();
        write_uuid(&mut buf, &test.to_string()).unwrap();
        let msg = buf.clone();
        let mut decode_data = msg.as_slice();
        let decoded = read_uuid(&mut decode_data).unwrap();
        assert_eq!(test.simple().to_string(), decoded);
    }

    #[test]
    fn test_write_read_time() {
        let test = Local::now().trunc_subsecs(0);
        let mut buf = Vec::with_capacity(36);
        write_time(&mut buf, test.into()).unwrap();
        let msg = buf.clone();
        let mut decode_data = msg.as_slice();
        let decoded = read_time(&mut decode_data).unwrap();
        assert_eq!(test, decoded);
    }

    #[test]
    fn test_write_audit_ids() {
        let test = vec!["Zm9vCg".into()];
        let mut buf = Vec::with_capacity(36);
        write_audit_ids(&mut buf, test.clone()).unwrap();
        let msg = buf.clone();
        let mut decode_data = msg.as_slice();
        let decoded: Vec<String> = read_audit_ids(&mut decode_data)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(test, decoded);
    }

    #[test]
    fn test_write_bool() {
        let test = true;
        let mut buf = Vec::with_capacity(1);
        write_bool(&mut buf, test).unwrap();
        let msg = buf.clone();
        let mut decode_data = msg.as_slice();
        let decoded = read_bool(&mut decode_data).unwrap();
        assert_eq!(test, decoded);
    }

    #[test]
    fn test_write_read_uuid_long_non_uuid_str() {
        // Non-UUID ids are written as raw bytes (`write_bin`), which switches
        // from a `Bin8` to a `Bin16` marker at 256 bytes and uses a raw
        // (non-MessagePack) length byte/word either way. Exercise both the
        // >=128 (still Bin8) and >=256 (Bin16) boundaries.
        for len in [150, 300] {
            let long_id = "a".repeat(len);
            let mut buf = Vec::new();
            write_uuid(&mut buf, &long_id).unwrap();
            let mut decode_data = buf.as_slice();
            let decoded = read_uuid(&mut decode_data).unwrap();
            assert_eq!(long_id, decoded);
        }
    }

    #[test]
    fn test_write_read_str_long() {
        // `write_str` switches from `FixStr` to `Str8`/`Str16` at 32/256
        // bytes; `read_str` must understand all of them.
        for len in [10, 32, 100, 300] {
            let long_str = "a".repeat(len);
            let mut buf = Vec::new();
            write_str(&mut buf, &long_str).unwrap();
            let mut decode_data = buf.as_slice();
            let decoded = read_str(&mut decode_data).unwrap();
            assert_eq!(long_str, decoded);
        }
    }

    #[test]
    fn test_write_read_auth_methods_code_full_range() {
        for code in [1u8, 64, 127, 128, 200, 255] {
            let mut buf = Vec::new();
            write_auth_methods_code(&mut buf, code).unwrap();
            let mut decode_data = buf.as_slice();
            let decoded = read_auth_methods_code(&mut decode_data).unwrap();
            assert_eq!(code, decoded);
        }
    }
}
