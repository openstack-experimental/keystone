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
//! Mapping provider error type.

use thiserror::Error;
use validator::ValidationErrors;

use crate::error::BuilderError;

/// Mapping provider error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum MappingProviderError {
    /// Mapping not found.
    #[error("mapping ruleset `{0}` is not found")]
    NotFound(String),

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Driver error.
    #[error("backend driver error: {source}")]
    Driver {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Raft storage is not available.
    #[error("raft storage is not available in the mapping provider")]
    RaftNotAvailable,

    /// Raft storage error.
    #[error("raft storage error in the mapping provider: {source}")]
    RaftStoreError {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder(#[from] Box<BuilderError>),

    /// Unsupported driver.
    #[error("unsupported driver `{0}` for the mapping provider")]
    UnsupportedDriver(String),

    /// Request validation error (from `validator` crate).
    #[error("request validation error: {source}")]
    Validation {
        #[source]
        source: ValidationErrors,
    },

    /// Regex pattern `{0}` is syntactically invalid.
    #[error("regex pattern `{0}` is syntactically invalid")]
    InvalidRegexSyntax(String),

    /// Regex pattern `{0}` exceeds complexity limit (AST size > 4096).
    #[error("regex pattern `{0}` exceeds complexity limit (AST size > 4096)")]
    RegexTooComplex(String),

    /// Regex pattern `{0}` fails write-time ReDoS safety check: `{1}`.
    #[error("regex pattern `{0}` fails write-time ReDoS safety check: {1}")]
    RegexSafetyViolation(String, String),

    /// Template references reserved key `{0}`.
    #[error("template references reserved key: {0}")]
    SystemTokenShadowing(String),

    /// Rule name `{0}` is not a valid identifier.
    #[error("rule name '{0}' is not a valid identifier")]
    InvalidRuleName(String),

    /// Duplicate rule name `{0}` within ruleset.
    #[error("duplicate rule name '{0}' within ruleset")]
    DuplicateRuleName(String),

    /// `ClaimsOnly` mode requires `user_domain_id` template with a claims
    /// reference.
    #[error(
        "ClaimsOnly mode requires user_domain_id template with a claims interpolation reference"
    )]
    DomainClaimRequired,

    /// `Fixed` mode does not allow claims templates in `user_domain_id`.
    #[error("Fixed mode does not allow claims templates in user_domain_id")]
    DomainOverrideInFixedMode,

    /// Interpolated value exceeds 256 character limit.
    #[error("interpolated value exceeds 256 character limit")]
    InterpolatedValueTooLong,

    /// Ruleset `{0}` contains `is_system` rules and is immutable.
    #[error("mapping ruleset `{0}` is an immutable system mapping and cannot be modified")]
    RulesetImmutable(String),

    /// No matching rule found for the provided claims.
    #[error("no matching rule found for the provided claims")]
    NoMatchingRule,

    /// Target ruleset is disabled.
    #[error("target mapping ruleset is disabled")]
    DisabledRuleset,

    /// Requested mapping rule `{0}` was not found in the ruleset.
    #[error("requested mapping rule '{0}' was not found")]
    MappingRuleNotFound(String),

    /// Concurrent modification conflict (CAS/revision mismatch).
    #[error("concurrent modification conflict: {subject} — {description}")]
    CasConflict {
        subject: String,
        description: String,
    },

    /// HMAC-SHA256 derivation failed (salt unavailable or invalid).
    #[error("HMAC-SHA256 virtual user ID derivation failed: {0}")]
    HmacDerivationFailed(String),

    /// `allowed_domains` list exceeds cardinality limit ({0}).
    #[error("allowed_domains list exceeds cardinality limit of {0}")]
    AllowedDomainsTooLarge(usize),
}

impl MappingProviderError {
    /// Create a Raft storage error.
    pub fn raft<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::RaftStoreError {
            source: Box::new(source),
        }
    }
}

impl From<ValidationErrors> for MappingProviderError {
    fn from(value: ValidationErrors) -> Self {
        Self::Validation { source: value }
    }
}
