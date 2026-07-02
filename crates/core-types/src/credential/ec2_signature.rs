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
//! # EC2 token signature request (ADR 0019 §5)

use std::collections::HashMap;

use derive_builder::Builder;

use crate::error::BuilderError;

/// The `credentials` object accepted by `POST /v3/ec2tokens`, mirroring the
/// payload produced by `keystoneclient.contrib.ec2.utils.Ec2Signer` and
/// consumed by Python Keystone's `EC2TokensResource._check_signature()`.
#[derive(Builder, Clone, Debug, Default, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Ec2SignatureRequest {
    /// The EC2 access key identifying the credential record.
    pub access: String,

    /// The client-supplied signature to verify against the server-generated
    /// one. `None` is treated as "signature not supplied" (401).
    #[builder(default)]
    pub signature: Option<String>,

    /// The `Host` the request was signed against (used by the v2 string to
    /// sign, and subject to the boto/port-stripping fallback).
    #[builder(default)]
    pub host: String,

    /// The HTTP verb the request was signed with (e.g. `GET`, `POST`).
    #[builder(default)]
    pub verb: String,

    /// The HTTP path the request was signed against.
    #[builder(default)]
    pub path: String,

    /// Query parameters included in the signed request (v0/v1/v2 carry the
    /// signature material here; v4 mostly leaves this empty in favour of the
    /// `Authorization` header).
    #[builder(default)]
    pub params: HashMap<String, String>,

    /// Headers included in the signed request (used by v4 SigV4 signing).
    #[builder(default)]
    pub headers: HashMap<String, String>,

    /// SHA-256 hex digest of the request body. Required for v4; use the
    /// empty-string hash for bodyless requests.
    #[builder(default)]
    pub body_hash: Option<String>,
}
