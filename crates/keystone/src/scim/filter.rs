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
//! # SCIM `filter` query grammar (ADR 0024 §5.B)
//!
//! A deliberately narrow subset of RFC 7644 filtering: a homogeneous
//! `and`/`or` chain of `ATTR OP [value]` terms, five operators, and a
//! per-resource attribute allowlist. Anything else -- mixed logical
//! operators, nested/parenthesized expressions, an attribute or operator
//! outside the table, or a filter exceeding the size/term caps -- is
//! rejected with `400 invalidFilter` before it ever reaches a handler's
//! resource lookup.

use crate::scim::error::ScimApiError;

/// Hard caps from ADR 0024 §5.B, matching the DoS-hardening posture used
/// elsewhere in the codebase (regex/claim size bounds, rate limiting).
const MAX_FILTER_BYTES: usize = 512;
const MAX_FILTER_TERMS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOp {
    Eq,
    Ne,
    Co,
    Sw,
    Pr,
}

impl FilterOp {
    fn parse(token: &str) -> Option<Self> {
        match token.to_ascii_lowercase().as_str() {
            "eq" => Some(Self::Eq),
            "ne" => Some(Self::Ne),
            "co" => Some(Self::Co),
            "sw" => Some(Self::Sw),
            "pr" => Some(Self::Pr),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalOp {
    And,
    Or,
}

/// One allowlisted attribute and the operators §5.B permits against it.
pub struct FilterAttr {
    pub name: &'static str,
    pub ops: &'static [FilterOp],
}

/// ADR 0024 §5.B User attribute table.
pub const USER_FILTER_ATTRS: &[FilterAttr] = &[
    FilterAttr {
        name: "username",
        ops: &[
            FilterOp::Eq,
            FilterOp::Ne,
            FilterOp::Co,
            FilterOp::Sw,
            FilterOp::Pr,
        ],
    },
    FilterAttr {
        name: "externalid",
        ops: &[FilterOp::Eq, FilterOp::Ne, FilterOp::Pr],
    },
    FilterAttr {
        name: "id",
        ops: &[FilterOp::Eq, FilterOp::Pr],
    },
    FilterAttr {
        name: "active",
        ops: &[FilterOp::Eq, FilterOp::Pr],
    },
];

/// ADR 0024 §5.B Group attribute table.
pub const GROUP_FILTER_ATTRS: &[FilterAttr] = &[
    FilterAttr {
        name: "displayname",
        ops: &[
            FilterOp::Eq,
            FilterOp::Ne,
            FilterOp::Co,
            FilterOp::Sw,
            FilterOp::Pr,
        ],
    },
    FilterAttr {
        name: "externalid",
        ops: &[FilterOp::Eq, FilterOp::Ne, FilterOp::Pr],
    },
    FilterAttr {
        name: "id",
        ops: &[FilterOp::Eq, FilterOp::Pr],
    },
];

#[derive(Debug, Clone)]
pub struct FilterTerm {
    /// Lowercased attribute name, already validated against the table.
    pub attr: String,
    pub op: FilterOp,
    pub value: Option<String>,
}

impl FilterTerm {
    fn matches(&self, actual: Option<&str>) -> bool {
        match self.op {
            FilterOp::Pr => actual.is_some_and(|v| !v.is_empty()),
            FilterOp::Eq => match (actual, &self.value) {
                (Some(a), Some(v)) => {
                    if self.attr == "id" {
                        a == v
                    } else {
                        a.eq_ignore_ascii_case(v)
                    }
                }
                _ => false,
            },
            FilterOp::Ne => match (actual, &self.value) {
                (Some(a), Some(v)) => {
                    if self.attr == "id" {
                        a != v
                    } else {
                        !a.eq_ignore_ascii_case(v)
                    }
                }
                _ => true,
            },
            FilterOp::Co => match (actual, &self.value) {
                (Some(a), Some(v)) => a.to_lowercase().contains(&v.to_lowercase()),
                _ => false,
            },
            FilterOp::Sw => match (actual, &self.value) {
                (Some(a), Some(v)) => a.to_lowercase().starts_with(&v.to_lowercase()),
                _ => false,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedFilter {
    pub terms: Vec<FilterTerm>,
    pub logical_op: Option<LogicalOp>,
}

impl ParsedFilter {
    /// Evaluate against a resource, resolving each term's attribute value
    /// via `resolve` (a per-resource closure over its hydrated fields).
    pub fn matches(&self, resolve: impl Fn(&str) -> Option<String>) -> bool {
        let mut results = self
            .terms
            .iter()
            .map(|t| t.matches(resolve(&t.attr).as_deref()));
        match self.logical_op {
            Some(LogicalOp::Or) => results.any(|b| b),
            _ => results.all(|b| b),
        }
    }
}

/// Tokenize respecting double-quoted string values, so a quoted value can
/// itself contain whitespace (e.g. `displayName eq "Site Admins"`).
fn tokenize(input: &str) -> Result<Vec<String>, ScimApiError> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == '"' {
            chars.next();
            let mut value = String::new();
            let mut closed = false;
            for c in chars.by_ref() {
                if c == '"' {
                    closed = true;
                    break;
                }
                value.push(c);
            }
            if !closed {
                return Err(ScimApiError::InvalidFilter(
                    "unterminated quoted value".to_string(),
                ));
            }
            tokens.push(value);
        } else {
            let mut value = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                value.push(c);
                chars.next();
            }
            tokens.push(value);
        }
    }
    Ok(tokens)
}

/// Parse and validate a `filter` query parameter against `table`. Rejects
/// anything outside the ADR 0024 §5.B grammar with `ScimApiError::
/// InvalidFilter` (400, `scimType: "invalidFilter"`).
pub fn parse_filter(raw: &str, table: &[FilterAttr]) -> Result<ParsedFilter, ScimApiError> {
    if raw.len() > MAX_FILTER_BYTES {
        return Err(ScimApiError::InvalidFilter(format!(
            "filter exceeds the {MAX_FILTER_BYTES}-byte limit"
        )));
    }

    let tokens = tokenize(raw)?;
    if tokens.is_empty() {
        return Err(ScimApiError::InvalidFilter("empty filter".to_string()));
    }

    let mut terms = Vec::new();
    let mut logical_op: Option<LogicalOp> = None;
    let mut i = 0;
    loop {
        if terms.len() >= MAX_FILTER_TERMS {
            return Err(ScimApiError::InvalidFilter(format!(
                "filter exceeds the {MAX_FILTER_TERMS}-term limit"
            )));
        }
        let Some(attr_token) = tokens.get(i) else {
            return Err(ScimApiError::InvalidFilter(
                "expected an attribute name".to_string(),
            ));
        };
        let attr_lower = attr_token.to_ascii_lowercase();
        let Some(entry) = table.iter().find(|a| a.name == attr_lower) else {
            return Err(ScimApiError::InvalidFilter(format!(
                "attribute `{attr_token}` is not filterable"
            )));
        };
        let Some(op_token) = tokens.get(i + 1) else {
            return Err(ScimApiError::InvalidFilter(
                "expected a filter operator".to_string(),
            ));
        };
        let Some(op) = FilterOp::parse(op_token) else {
            return Err(ScimApiError::InvalidFilter(format!(
                "unsupported operator `{op_token}`"
            )));
        };
        if !entry.ops.contains(&op) {
            return Err(ScimApiError::InvalidFilter(format!(
                "operator `{op_token}` is not allowed on `{attr_token}`"
            )));
        }

        let (value, consumed) = if op == FilterOp::Pr {
            (None, 2)
        } else {
            let Some(value_token) = tokens.get(i + 2) else {
                return Err(ScimApiError::InvalidFilter(format!(
                    "expected a value for `{attr_token} {op_token}`"
                )));
            };
            (Some(value_token.clone()), 3)
        };

        terms.push(FilterTerm {
            attr: attr_lower,
            op,
            value,
        });
        i += consumed;

        match tokens.get(i) {
            None => break,
            Some(sep) => {
                let sep_op = match sep.to_ascii_lowercase().as_str() {
                    "and" => LogicalOp::And,
                    "or" => LogicalOp::Or,
                    other => {
                        return Err(ScimApiError::InvalidFilter(format!(
                            "expected `and`/`or`, found `{other}`"
                        )));
                    }
                };
                match logical_op {
                    None => logical_op = Some(sep_op),
                    Some(existing) if existing == sep_op => {}
                    Some(_) => {
                        return Err(ScimApiError::InvalidFilter(
                            "`and` and `or` must not be mixed in one filter".to_string(),
                        ));
                    }
                }
                i += 1;
            }
        }
    }

    Ok(ParsedFilter { terms, logical_op })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_eq_term() {
        let parsed = parse_filter(r#"userName eq "alice""#, USER_FILTER_ATTRS).unwrap();
        assert_eq!(parsed.terms.len(), 1);
        assert!(parsed.matches(|attr| (attr == "username").then(|| "alice".to_string())));
        assert!(!parsed.matches(|attr| (attr == "username").then(|| "bob".to_string())));
    }

    #[test]
    fn test_parse_pr_term_no_value() {
        let parsed = parse_filter("externalId pr", USER_FILTER_ATTRS).unwrap();
        assert!(parsed.matches(|_| Some("anything".to_string())));
        assert!(!parsed.matches(|_| None));
    }

    #[test]
    fn test_parse_and_chain() {
        let parsed = parse_filter(
            r#"userName sw "al" and active eq "true""#,
            USER_FILTER_ATTRS,
        )
        .unwrap();
        assert!(parsed.matches(|attr| match attr {
            "username" => Some("alice".to_string()),
            "active" => Some("true".to_string()),
            _ => None,
        }));
        assert!(!parsed.matches(|attr| match attr {
            "username" => Some("bob".to_string()),
            "active" => Some("true".to_string()),
            _ => None,
        }));
    }

    #[test]
    fn test_parse_or_chain() {
        let parsed = parse_filter(
            r#"userName eq "alice" or userName eq "bob""#,
            USER_FILTER_ATTRS,
        )
        .unwrap();
        assert!(parsed.matches(|_| Some("bob".to_string())));
        assert!(!parsed.matches(|_| Some("carol".to_string())));
    }

    #[test]
    fn test_reject_mixed_and_or() {
        let result = parse_filter(
            r#"userName eq "a" and active pr or externalId pr"#,
            USER_FILTER_ATTRS,
        );
        assert!(matches!(result, Err(ScimApiError::InvalidFilter(_))));
    }

    #[test]
    fn test_reject_disallowed_attribute() {
        let result = parse_filter(r#"password eq "x""#, USER_FILTER_ATTRS);
        assert!(matches!(result, Err(ScimApiError::InvalidFilter(_))));
    }

    #[test]
    fn test_reject_disallowed_operator_for_attribute() {
        // `co` is not permitted on `id` per the §5.B table.
        let result = parse_filter(r#"id co "abc""#, USER_FILTER_ATTRS);
        assert!(matches!(result, Err(ScimApiError::InvalidFilter(_))));
    }

    #[test]
    fn test_reject_oversized_filter() {
        let huge = format!(r#"userName eq "{}""#, "a".repeat(600));
        let result = parse_filter(&huge, USER_FILTER_ATTRS);
        assert!(matches!(result, Err(ScimApiError::InvalidFilter(_))));
    }

    #[test]
    fn test_reject_too_many_terms() {
        let filter = (0..9)
            .map(|_| r#"externalId pr"#)
            .collect::<Vec<_>>()
            .join(" and ");
        let result = parse_filter(&filter, USER_FILTER_ATTRS);
        assert!(matches!(result, Err(ScimApiError::InvalidFilter(_))));
    }

    #[test]
    fn test_group_attrs_reject_username() {
        let result = parse_filter(r#"userName eq "x""#, GROUP_FILTER_ATTRS);
        assert!(matches!(result, Err(ScimApiError::InvalidFilter(_))));
    }

    #[test]
    fn test_group_displayname_filter() {
        let parsed = parse_filter(r#"displayName eq "Engineers""#, GROUP_FILTER_ATTRS).unwrap();
        assert!(parsed.matches(|attr| (attr == "displayname").then(|| "engineers".to_string())));
    }
}
