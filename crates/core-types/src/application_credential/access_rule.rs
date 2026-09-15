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
//! # Application credential access rule

use derive_builder::Builder;
use serde::Serialize;
use validator::Validate;

use crate::error::BuilderError;

/// The application credential access rule object.
#[derive(Builder, Clone, Debug, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct AccessRule {
    /// The ID of the access rule.
    #[validate(length(min = 1, max = 64))]
    pub id: String,

    /// The request method that the application credential is permitted to use
    /// for a given API endpoint.
    #[builder(default)]
    #[validate(length(min = 1, max = 16))]
    pub method: Option<String>,

    /// The API path that the application credential is permitted to access.
    /// May use named wildcards such as {tag} or the unnamed wildcard `*` to
    /// match against any string in the path up to a `/`, or the recursive
    /// wildcard `**` to include `/` in the matched path.
    #[builder(default)]
    #[validate(length(min = 1, max = 128))]
    pub path: Option<String>,

    /// The service type identifier for the service that the application
    /// credential is permitted to access. Must be a service type that is
    /// listed in the service catalog and not a code name for a service.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub service: Option<String>,

    /// The ID of the user who owns the access rule.
    // TODO: modify DB so that user_id is not nullable
    #[validate(length(min = 1, max = 64))]
    pub user_id: String,
}

/// Keystone's own service type, as registered in the catalog and as the
/// value every access rule restricting calls *to Keystone itself* must
/// carry in its `service` field (matches upstream OpenStack convention).
///
/// Application-credential `access_rules` name the service, method, and path
/// of an API call the credential is permitted to make. When that call
/// targets a different OpenStack service (compute, image, ...), enforcement
/// is that service's own keystonemiddleware's job -- it fetches the rules
/// via token introspection and checks the incoming request itself. Keystone
/// only needs to (and only safely can) self-enforce the subset of rules
/// naming its own service, which is what [`access_rules_permit`] checks.
pub const OWN_SERVICE_TYPE: &str = "identity";

/// True if `rules` (a non-empty, restricting `AccessRule` list) contains at
/// least one rule permitting `method`/`path` against Keystone's own service
/// (see [`OWN_SERVICE_TYPE`]). Method comparison is case-insensitive
/// (`GET`/`get`); a rule missing `method`, `path`, or `service` never
/// matches anything -- those fields are required at the API layer, but a
/// permissive read here would fail open on a malformed stored rule, which
/// is the wrong failure direction for an authorization gate.
pub fn access_rules_permit(rules: &[AccessRule], method: &str, path: &str) -> bool {
    rules.iter().any(|rule| rule_matches(rule, method, path))
}

fn rule_matches(rule: &AccessRule, method: &str, path: &str) -> bool {
    let Some(rule_service) = rule.service.as_deref() else {
        return false;
    };
    if !rule_service.eq_ignore_ascii_case(OWN_SERVICE_TYPE) {
        return false;
    }
    let Some(rule_method) = rule.method.as_deref() else {
        return false;
    };
    if !rule_method.eq_ignore_ascii_case(method) {
        return false;
    }
    let Some(rule_path) = rule.path.as_deref() else {
        return false;
    };
    path_matches(rule_path, path)
}

/// Matches `path` against the `AccessRule.path` wildcard syntax documented
/// on the struct above: `{tag}`/`*` match exactly one path segment, `**`
/// matches zero or more segments (including across `/`), and any other
/// segment must match literally. Comparison is segment-wise, not a byte
/// prefix/suffix match, so `/v3/users` never matches a rule path of
/// `/v3/users2` or vice versa.
fn path_matches(pattern: &str, path: &str) -> bool {
    let pattern_segs: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let path_segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    segments_match(&pattern_segs, &path_segs)
}

fn segments_match(pattern: &[&str], path: &[&str]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((&"**", rest)) => (0..=path.len()).any(|i| segments_match(rest, &path[i..])),
        Some((seg, rest)) => match path.split_first() {
            None => false,
            Some((p, prest)) => {
                let seg_matches =
                    *seg == "*" || (seg.starts_with('{') && seg.ends_with('}')) || seg == p;
                seg_matches && segments_match(rest, prest)
            }
        },
    }
}

/// The application credential access rule object to be created.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct AccessRuleCreate {
    /// The ID of the access rule.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,

    /// The request method that the application credential is permitted to use
    /// for a given API endpoint.
    #[builder(default)]
    #[validate(length(min = 1, max = 16))]
    pub method: Option<String>,

    /// The API path that the application credential is permitted to access.
    /// May use named wildcards such as {tag} or the unnamed wildcard `*` to
    /// match against any string in the path up to a `/`, or the recursive
    /// wildcard `**` to include `/` in the matched path.
    #[builder(default)]
    #[validate(length(min = 1, max = 128))]
    pub path: Option<String>,

    /// The service type identifier for the service that the application
    /// credential is permitted to access. Must be a service type that is
    /// listed in the service catalog and not a code name for a service.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub service: Option<String>,

    /// The ID of the user who owns the access rule.
    // TODO: modify DB so that user_id is not nullable
    #[validate(length(min = 1, max = 64))]
    pub user_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(method: &str, path: &str, service: &str) -> AccessRule {
        AccessRuleBuilder::default()
            .id("r1")
            .method(method.to_string())
            .path(path.to_string())
            .service(service.to_string())
            .user_id("u1")
            .build()
            .unwrap()
    }

    #[test]
    fn test_literal_path_matches() {
        let rules = vec![rule("GET", "/v3/users", "identity")];
        assert!(access_rules_permit(&rules, "GET", "/v3/users"));
        assert!(!access_rules_permit(&rules, "GET", "/v3/users/1"));
        assert!(!access_rules_permit(&rules, "POST", "/v3/users"));
    }

    #[test]
    fn test_method_is_case_insensitive() {
        let rules = vec![rule("get", "/v3/users", "identity")];
        assert!(access_rules_permit(&rules, "GET", "/v3/users"));
    }

    #[test]
    fn test_wrong_service_never_matches() {
        // A rule scoped to another service must never authorize a call
        // against Keystone's own API, even if method/path happen to line up.
        let rules = vec![rule("GET", "/v3/users", "compute")];
        assert!(!access_rules_permit(&rules, "GET", "/v3/users"));
    }

    #[test]
    fn test_named_wildcard_matches_one_segment() {
        let rules = vec![rule("GET", "/v3/users/{user_id}", "identity")];
        assert!(access_rules_permit(&rules, "GET", "/v3/users/abc123"));
        assert!(!access_rules_permit(&rules, "GET", "/v3/users"));
        assert!(!access_rules_permit(&rules, "GET", "/v3/users/abc/roles"));
    }

    #[test]
    fn test_unnamed_wildcard_matches_one_segment() {
        let rules = vec![rule("GET", "/v3/users/*", "identity")];
        assert!(access_rules_permit(&rules, "GET", "/v3/users/abc123"));
        assert!(!access_rules_permit(&rules, "GET", "/v3/users/abc/roles"));
    }

    #[test]
    fn test_recursive_wildcard_matches_across_slashes() {
        let rules = vec![rule("GET", "/v3/users/**", "identity")];
        assert!(access_rules_permit(&rules, "GET", "/v3/users/abc123"));
        assert!(access_rules_permit(
            &rules,
            "GET",
            "/v3/users/abc123/roles/def456"
        ));
        assert!(access_rules_permit(&rules, "GET", "/v3/users"));
        assert!(!access_rules_permit(&rules, "GET", "/v3/projects"));
    }

    #[test]
    fn test_no_rules_permits_nothing() {
        assert!(!access_rules_permit(&[], "GET", "/v3/users"));
    }

    #[test]
    fn test_rule_missing_optional_field_never_matches() {
        let mut r = rule("GET", "/v3/users", "identity");
        r.method = None;
        assert!(!access_rules_permit(&[r.clone()], "GET", "/v3/users"));

        let mut r2 = rule("GET", "/v3/users", "identity");
        r2.path = None;
        assert!(!access_rules_permit(&[r2], "GET", "/v3/users"));

        let mut r3 = rule("GET", "/v3/users", "identity");
        r3.service = None;
        assert!(!access_rules_permit(&[r3], "GET", "/v3/users"));
    }

    #[test]
    fn test_any_matching_rule_in_list_permits() {
        let rules = vec![
            rule("GET", "/v3/projects", "identity"),
            rule("POST", "/v3/users", "identity"),
        ];
        assert!(access_rules_permit(&rules, "POST", "/v3/users"));
        assert!(!access_rules_permit(&rules, "DELETE", "/v3/users"));
    }
}
