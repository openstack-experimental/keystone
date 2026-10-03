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
//! # Audit coverage check
//!
//! ADR 0023 promises that every state-changing provider operation is audited
//! fail-closed. This test walks the `service.rs` of every provider, finds the
//! methods whose name says they change state and requires each to contain an
//! [`audited_op!`](crate::audited_op) or [`audited_if_ctx!`](crate::audited_if_ctx)
//! call site, or to be listed in [`ALLOW_LIST`] with the reason it is exempt.
//! A new provider (or a new mutating method) therefore cannot ship unaudited
//! without a reviewer seeing an explicit exemption.

use std::fs;
use std::path::Path;

/// Method name prefixes that denote a state change.
const MUTATING_PREFIXES: &[&str] = &[
    "create",
    "update",
    "delete",
    "remove",
    "revoke",
    "purge",
    "rotate",
    "stage",
    "confirm",
    "reconcile",
    "add",
    "set",
    "grant",
    "disable",
    "enable",
    "import",
];

/// Markers that make a method audited.
const AUDIT_MARKERS: &[&str] = &["audited_op!", "audited_if_ctx!"];

/// `(provider directory, method, reason)` of the mutating methods that are
/// deliberately not audited. Keep reasons specific: this list is the review
/// surface for "why is this not in the audit trail".
const ALLOW_LIST: &[(&str, &str, &str)] = &[
    (
        "api_key",
        "update_last_used",
        "bookkeeping of the last-use timestamp on every authentication; the \
         authentication itself is audited at the perimeter",
    ),
    (
        "api_key",
        "update_secret_hash",
        "transparent re-hash of the stored secret after a successful \
         authentication; no new credential is issued and nothing changes for \
         the owner",
    ),
    (
        "domain_config",
        "reconcile_registration_before",
        "private helper of the audited domain_config writes, which wrap the \
         whole sequence",
    ),
    (
        "domain_config",
        "reconcile_registration_after",
        "private helper of the audited domain_config writes, which wrap the \
         whole sequence",
    ),
    (
        "oauth2_client",
        "revoke_client_families",
        "private helper called inside the audited client delete and disable",
    ),
    (
        "oauth2_session",
        "revoke_refresh_token_family",
        "audited by the OAuth2 handlers with the revocation reason (refresh \
         token family revoked event, including reuse detection)",
    ),
    (
        "oauth2_session",
        "revoke_refresh_token_families_by_client",
        "called inside the audited OAuth2 client delete and disable",
    ),
    (
        "oauth2_session",
        "purge_expired",
        "janitor housekeeping of expired sessions",
    ),
    (
        "oauth2_key",
        "ensure_domain_keys",
        "idempotent first-use provisioning triggered by the domain-creation \
         event, which is audited itself",
    ),
    (
        "oauth2_key",
        "revoke_jti",
        "recorded by the fail-closed emergency-rotation event that revokes the \
         JTIs",
    ),
    (
        "oauth2_key",
        "retire_previous_key",
        "janitor housekeeping after a rotation, which is audited",
    ),
    (
        "oauth2_key",
        "prune_expired_jtis",
        "janitor housekeeping of expired entries",
    ),
];

/// Extract `(method name, body)` of every `async fn` in `source`.
fn methods(source: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut rest = source;
    while let Some(pos) = rest.find("async fn ") {
        let after = &rest[pos + "async fn ".len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let Some(open) = after.find('{') else { break };
        // A trait-style declaration ends in `;` before any body.
        let declaration_end = after.find(';').unwrap_or(usize::MAX);
        if declaration_end < open {
            rest = &after[declaration_end..];
            continue;
        }
        let mut depth = 0usize;
        let mut end = after.len();
        for (i, c) in after[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        found.push((name, after[open..end].to_string()));
        rest = &after[end..];
    }
    found
}

/// The production part of a service file: everything before its test module.
fn production_source(source: &str) -> &str {
    source
        .find("#[cfg(test)]")
        .map_or(source, |idx| &source[..idx])
}

#[test]
fn every_mutating_provider_method_is_audited_or_allow_listed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut unaudited = Vec::new();
    let mut providers = 0;

    let mut dirs: Vec<_> = fs::read_dir(&root)
        .expect("read src")
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .collect();
    dirs.sort_by_key(|e| e.file_name());

    for dir in dirs {
        let provider = dir.file_name().to_string_lossy().to_string();
        let service = dir.path().join("service.rs");
        let Ok(source) = fs::read_to_string(&service) else {
            continue;
        };
        providers += 1;
        for (name, body) in methods(production_source(&source)) {
            if !MUTATING_PREFIXES
                .iter()
                .any(|p| name == *p || name.starts_with(&format!("{p}_")))
            {
                continue;
            }
            if AUDIT_MARKERS.iter().any(|m| body.contains(m)) {
                continue;
            }
            if ALLOW_LIST
                .iter()
                .any(|(p, m, _)| *p == provider && *m == name)
            {
                continue;
            }
            unaudited.push(format!("{provider}::{name}"));
        }
    }

    assert!(providers > 10, "found only {providers} provider services");
    assert!(
        unaudited.is_empty(),
        "mutating provider methods without an audited_op!/audited_if_ctx! call \
         site (wrap them, or add an ALLOW_LIST entry with a reason):\n  {}",
        unaudited.join("\n  ")
    );
}

#[test]
fn allow_list_entries_name_existing_methods_and_carry_a_reason() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for (provider, method, reason) in ALLOW_LIST {
        assert!(
            reason.len() > 20,
            "{provider}::{method}: give a real reason"
        );
        let source = fs::read_to_string(root.join(provider).join("service.rs"))
            .unwrap_or_else(|_| panic!("{provider}/service.rs must exist"));
        assert!(
            methods(production_source(&source))
                .iter()
                .any(|(name, _)| name == method),
            "stale ALLOW_LIST entry {provider}::{method}"
        );
    }
}
