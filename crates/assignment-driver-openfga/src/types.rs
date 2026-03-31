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
//! # OpenFGA object mapping
//!
//! Keystone entities are mapped onto OpenFGA objects purely from
//! configuration (`[openfga]` opts) - there is no per-entity lookup and no
//! reverse-mapping store. See `docs/design-actor-mapping.md` in the reference
//! Python plugin for the rationale (Keystone's internal `id_mapping` table is
//! a shared public<->local routing table and is the wrong mechanism here).
//!
//! A Keystone entity is `(kind, id)` with `kind` one of `user`, `group`,
//! `project`, `domain`, `system`. Each kind has a list of OpenFGA type names:
//! the first is *canonical* (used for writes) and every entry is consulted on
//! reads, checks and deletes. The same id transform applies to actors and
//! targets alike.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use openstack_keystone_config::{OpenFGAAssignmentDriver, OpenFGAIdTransform};
use openstack_keystone_core::assignment::AssignmentProviderError;
use openstack_keystone_core_types::assignment::*;

/// A Keystone entity kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    User,
    Group,
    Project,
    Domain,
    System,
}

impl Kind {
    /// All kinds, in a fixed order (used for reverse type-name lookup).
    pub(crate) const ALL: [Kind; 5] = [
        Kind::User,
        Kind::Group,
        Kind::Project,
        Kind::Domain,
        Kind::System,
    ];

    /// Whether this kind is an actor (`user`/`group`) rather than a target.
    #[cfg(test)]
    pub(crate) fn is_actor(&self) -> bool {
        matches!(self, Kind::User | Kind::Group)
    }

    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Kind::User => "user",
            Kind::Group => "group",
            Kind::Project => "project",
            Kind::Domain => "domain",
            Kind::System => "system",
        }
    }
}

/// Split an [`AssignmentType`] into its `(actor kind, target kind)`.
pub(crate) fn assignment_type_kinds(t: &AssignmentType) -> (Kind, Kind) {
    match t {
        AssignmentType::UserProject => (Kind::User, Kind::Project),
        AssignmentType::UserDomain => (Kind::User, Kind::Domain),
        AssignmentType::UserSystem => (Kind::User, Kind::System),
        AssignmentType::GroupProject => (Kind::Group, Kind::Project),
        AssignmentType::GroupDomain => (Kind::Group, Kind::Domain),
        AssignmentType::GroupSystem => (Kind::Group, Kind::System),
    }
}

/// Recombine an actor kind and a target kind into an [`AssignmentType`].
///
/// Returns `None` when the pairing is nonsensical (e.g. an actor kind in the
/// target slot), which can happen for a hand-written OpenFGA tuple whose type
/// names collide across the configured kind lists.
pub(crate) fn kinds_to_assignment_type(actor: Kind, target: Kind) -> Option<AssignmentType> {
    Some(match (actor, target) {
        (Kind::User, Kind::Project) => AssignmentType::UserProject,
        (Kind::User, Kind::Domain) => AssignmentType::UserDomain,
        (Kind::User, Kind::System) => AssignmentType::UserSystem,
        (Kind::Group, Kind::Project) => AssignmentType::GroupProject,
        (Kind::Group, Kind::Domain) => AssignmentType::GroupDomain,
        (Kind::Group, Kind::System) => AssignmentType::GroupSystem,
        _ => return None,
    })
}

/// The actor `(kind, id)` a listing is scoped to, if any.
pub(crate) fn actor_from_list_parameters(
    params: &RoleAssignmentListParameters,
) -> Option<(Kind, &String)> {
    if let Some(user_id) = &params.user_id {
        Some((Kind::User, user_id))
    } else {
        params.group_id.as_ref().map(|g| (Kind::Group, g))
    }
}

/// The target `(kind, id)` a listing is scoped to, if any.
pub(crate) fn target_from_list_parameters(
    params: &RoleAssignmentListParameters,
) -> Option<(Kind, &String)> {
    if let Some(project_id) = &params.project_id {
        Some((Kind::Project, project_id))
    } else if let Some(domain_id) = &params.domain_id {
        Some((Kind::Domain, domain_id))
    } else {
        params.system_id.as_ref().map(|s| (Kind::System, s))
    }
}

/// Stateless, config-driven mapping between Keystone `(kind, id)` and OpenFGA
/// object strings (`"type:id"`).
#[derive(Debug, Clone)]
pub(crate) struct ObjectMapper {
    user_types: Vec<String>,
    group_types: Vec<String>,
    project_types: Vec<String>,
    domain_types: Vec<String>,
    system_types: Vec<String>,
    transform: OpenFGAIdTransform,
}

impl ObjectMapper {
    pub(crate) fn from_config(cfg: &OpenFGAAssignmentDriver) -> Self {
        Self {
            user_types: cfg.user_actor_types.clone(),
            group_types: cfg.group_actor_types.clone(),
            project_types: cfg.project_target_types.clone(),
            domain_types: cfg.domain_target_types.clone(),
            system_types: cfg.system_target_types.clone(),
            transform: cfg.id_transform,
        }
    }

    pub(crate) fn types_for(&self, kind: Kind) -> &[String] {
        match kind {
            Kind::User => &self.user_types,
            Kind::Group => &self.group_types,
            Kind::Project => &self.project_types,
            Kind::Domain => &self.domain_types,
            Kind::System => &self.system_types,
        }
    }

    /// Every OpenFGA object string a `(kind, id)` may be stored under.
    pub(crate) fn objects_for(&self, kind: Kind, keystone_id: &str) -> Vec<String> {
        let id = to_fga_id(self.transform, keystone_id);
        self.types_for(kind)
            .iter()
            .map(|t| format!("{t}:{id}"))
            .collect()
    }

    /// The single OpenFGA object string used when *writing* a `(kind, id)`.
    pub(crate) fn canonical_object(
        &self,
        kind: Kind,
        keystone_id: &str,
    ) -> Result<String, OpenFGADriverError> {
        let type_name = self
            .types_for(kind)
            .first()
            .ok_or(OpenFGADriverError::NoTypeConfigured(kind.as_str()))?;
        Ok(format!(
            "{type_name}:{}",
            to_fga_id(self.transform, keystone_id)
        ))
    }

    /// Inverse mapping: recover `(kind, keystone_id)` from an OpenFGA object
    /// string. `None` when the type name is not configured for any kind or the
    /// id part is empty.
    pub(crate) fn parse_object(&self, fga_object: &str) -> Option<(Kind, String)> {
        let (type_name, raw_id) = fga_object.split_once(':')?;
        if raw_id.is_empty() {
            return None;
        }
        let kind = self.kind_for_type(type_name)?;
        Some((kind, from_fga_id(self.transform, raw_id)))
    }

    /// The first kind whose configured type list contains `type_name`.
    fn kind_for_type(&self, type_name: &str) -> Option<Kind> {
        Kind::ALL
            .into_iter()
            .find(|kind| self.types_for(*kind).iter().any(|t| t == type_name))
    }
}

fn is_32_hex(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Keystone id -> OpenFGA id.
fn to_fga_id(transform: OpenFGAIdTransform, id: &str) -> String {
    match transform {
        OpenFGAIdTransform::None => id.to_string(),
        OpenFGAIdTransform::UuidDashes if is_32_hex(id) => format!(
            "{}-{}-{}-{}-{}",
            &id[0..8],
            &id[8..12],
            &id[12..16],
            &id[16..20],
            &id[20..32]
        ),
        OpenFGAIdTransform::UuidDashes => id.to_string(),
    }
}

/// OpenFGA id -> Keystone id.
fn from_fga_id(transform: OpenFGAIdTransform, id: &str) -> String {
    match transform {
        OpenFGAIdTransform::None => id.to_string(),
        OpenFGAIdTransform::UuidDashes => {
            let stripped: String = id.chars().filter(|c| *c != '-').collect();
            // Only collapse dashes when the result is a 32-hex UUID; leave any
            // other value (and its legitimate dashes) untouched.
            if is_32_hex(&stripped) {
                stripped
            } else {
                id.to_string()
            }
        }
    }
}

/// Collapse representation duplicates to one assignment each.
///
/// `Assignment` derives `Hash`/`Eq` over every field; the fan-out paths only
/// ever vary `actor_id`/`target_id`/`role_id`/`type` (the design's dedup key)
/// and always set `role_name`/`inherited`/`implied_via` to the same values, so
/// a plain set dedup is equivalent to keying on that tuple.
pub(crate) fn dedupe_assignments(items: Vec<Assignment>) -> Vec<Assignment> {
    let mut seen: HashSet<Assignment> = HashSet::new();
    items
        .into_iter()
        .filter(|a| seen.insert(a.clone()))
        .collect()
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGACheckResponse {
    pub(crate) allowed: bool,
    #[serde(default)]
    pub(crate) resolution: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGABatchCheckSingleResult {
    #[serde(default)]
    pub(crate) allowed: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGABatchCheckResponse {
    #[serde(default)]
    pub(crate) result: std::collections::HashMap<String, OpenFGABatchCheckSingleResult>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGAErrorResponse {
    #[serde(default)]
    pub(crate) code: String,
    pub(crate) message: String,
}

/// One newline-delimited frame of a `streamed-list-objects` response.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGAStreamedFrame {
    #[serde(default)]
    pub(crate) result: Option<OpenFGAStreamedObject>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGAStreamedObject {
    pub(crate) object: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGAReadResponse {
    #[serde(default)]
    pub(crate) tuples: Vec<OpenFGATupleKey>,
    #[serde(default)]
    pub(crate) continuation_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGATupleKey {
    #[serde(rename = "key")]
    pub(crate) tuple: OpenFGATuple,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGATuple {
    pub(crate) user: String,
    pub(crate) relation: String,
    pub(crate) object: String,
}

/// Assignment provider error.
#[derive(Error, Debug)]
pub enum OpenFGADriverError {
    /// Missing configuration for the openfga driver.
    #[error("openfga driver configuration missing")]
    MissingConfiguration,

    /// A kind has an empty OpenFGA type list, so no canonical object can be
    /// formed.
    #[error("no openfga type configured for kind `{0}`")]
    NoTypeConfigured(&'static str),

    /// Listing assignments knowing only the role is not supported.
    #[error("listing assignments by only the role is not supported by the openfga")]
    ListingAssignmentsByRoleNotSupported,

    /// Listing assignments without parameters is not supported.
    #[error("listing all assignments is not supported by the openfga")]
    ListingAllAssignmentsNotSupported,

    /// Listing an actor's assignments without a target scope, in non-effective
    /// mode. OpenFGA's `read` cannot enumerate tuples by user alone, so this
    /// query is only answerable via `list-objects` (i.e. `effective=true`).
    #[error(
        "listing an actor's assignments without a target scope requires effective mode \
         on the openfga driver"
    )]
    ListingActorWithoutScopeRequiresEffective,

    /// A `create_grant` asked for an inherited grant. The OpenFGA driver stores
    /// every grant as a single relationship tuple with no `inherited` marker, so
    /// an inherited grant would be indistinguishable from a direct one on read.
    /// Project-tree inheritance must instead be expressed in the OpenFGA
    /// authorization model; the request is rejected rather than silently
    /// downgraded to a direct grant.
    #[error("the openfga assignment driver does not support inherited grants")]
    InheritedGrantsNotSupported,

    /// An error response from the OpenFGA API. The payload is the parsed
    /// `message` field when the body is a recognised error envelope, otherwise
    /// the raw response body.
    #[error("openfga http error: {0}")]
    OpenFGAError(String),

    /// (de)serialize error.
    #[error(transparent)]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    /// Reqwest error.
    #[error(transparent)]
    Reqwest {
        #[from]
        source: reqwest::Error,
    },

    /// Role mapping not configured.
    #[error("role to relation mapping for the openfga driver is not configured for role `{0}`")]
    RoleRelationNotConfigured(String),

    /// Url parsing error.
    #[error(transparent)]
    Url {
        #[from]
        source: url::ParseError,
    },
}

impl From<OpenFGADriverError> for AssignmentProviderError {
    fn from(source: OpenFGADriverError) -> Self {
        match source {
            // A client-supplied `inherited: true` is a bad request, not a
            // backend fault - surface it as a 400, not a 500.
            OpenFGADriverError::InheritedGrantsNotSupported => {
                let mut errors = validator::ValidationErrors::new();
                errors.add(
                    "inherited",
                    validator::ValidationError::new("inherited_grants_unsupported"),
                );
                Self::Validation { source: errors }
            }
            // Caller-shape limitations, not backend faults: the query is
            // permanently unanswerable by this driver, regardless of retry.
            // Surface as 501, not a 500 `Driver` error.
            err @ (OpenFGADriverError::ListingActorWithoutScopeRequiresEffective
            | OpenFGADriverError::ListingAssignmentsByRoleNotSupported
            | OpenFGADriverError::ListingAllAssignmentsNotSupported) => {
                Self::NotImplemented(err.to_string())
            }
            other => Self::Driver(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use openstack_keystone_config::OpenFGAAssignmentDriver;
    use url::Url;

    use super::*;

    fn cfg() -> OpenFGAAssignmentDriver {
        OpenFGAAssignmentDriver {
            api_url: Url::parse("http://localhost/").unwrap(),
            api_key: None,
            model_id: None,
            store_id: "s".into(),
            timeout: None,
            max_retries: 0,
            retry_backoff_ms: 100,
            max_concurrency: 10,
            role_to_relation: None,
            user_actor_types: vec!["user".into()],
            group_actor_types: vec!["group".into()],
            project_target_types: vec!["project".into()],
            domain_target_types: vec!["domain".into()],
            system_target_types: vec!["system".into()],
            id_transform: OpenFGAIdTransform::None,
        }
    }

    #[test]
    fn defaults_reproduce_legacy_prefixes() {
        let m = ObjectMapper::from_config(&cfg());
        assert_eq!(m.canonical_object(Kind::User, "u1").unwrap(), "user:u1");
        assert_eq!(m.canonical_object(Kind::Group, "g1").unwrap(), "group:g1");
        assert_eq!(
            m.canonical_object(Kind::Project, "p1").unwrap(),
            "project:p1"
        );
        assert_eq!(
            m.canonical_object(Kind::Domain, "default").unwrap(),
            "domain:default"
        );
        assert_eq!(
            m.canonical_object(Kind::System, "all").unwrap(),
            "system:all"
        );
    }

    #[test]
    fn round_trip_all_kinds_default() {
        let m = ObjectMapper::from_config(&cfg());
        for (kind, id) in [
            (Kind::User, "u1"),
            (Kind::Group, "g1"),
            (Kind::Project, "p1"),
            (Kind::Domain, "default"),
            (Kind::System, "all"),
        ] {
            let obj = m.canonical_object(kind, id).unwrap();
            assert_eq!(m.parse_object(&obj), Some((kind, id.to_string())));
        }
    }

    #[test]
    fn parse_object_rejects_unknown_type_and_empty_id() {
        let m = ObjectMapper::from_config(&cfg());
        assert_eq!(m.parse_object("account:u1"), None);
        assert_eq!(m.parse_object("project:"), None);
        assert_eq!(m.parse_object("no-colon"), None);
    }

    #[test]
    fn custom_actor_types_fan_out_on_read_canonical_on_write() {
        let mut c = cfg();
        c.user_actor_types = vec!["user".into(), "account".into()];
        let m = ObjectMapper::from_config(&c);

        // write uses the first (canonical) type
        assert_eq!(m.canonical_object(Kind::User, "u1").unwrap(), "user:u1");
        // read fans out over every configured type
        assert_eq!(
            m.objects_for(Kind::User, "u1"),
            vec!["user:u1".to_string(), "account:u1".to_string()]
        );
        // a tuple stored under the alternate type still maps back
        assert_eq!(
            m.parse_object("account:u1"),
            Some((Kind::User, "u1".to_string()))
        );
    }

    #[test]
    fn custom_target_types_fan_out() {
        let mut c = cfg();
        c.project_target_types = vec!["project".into(), "proj".into()];
        let m = ObjectMapper::from_config(&c);
        assert_eq!(
            m.objects_for(Kind::Project, "p1"),
            vec!["project:p1".to_string(), "proj:p1".to_string()]
        );
        assert_eq!(
            m.parse_object("proj:p1"),
            Some((Kind::Project, "p1".to_string()))
        );
    }

    #[test]
    fn uuid_dashes_transform_both_directions() {
        let mut c = cfg();
        c.id_transform = OpenFGAIdTransform::UuidDashes;
        let m = ObjectMapper::from_config(&c);

        let dashless = "0123456789abcdef0123456789abcdef";
        let dashed = "01234567-89ab-cdef-0123-456789abcdef";

        assert_eq!(
            m.canonical_object(Kind::User, dashless).unwrap(),
            format!("user:{dashed}")
        );
        assert_eq!(
            m.parse_object(&format!("user:{dashed}")),
            Some((Kind::User, dashless.to_string()))
        );
    }

    #[test]
    fn uuid_dashes_passes_non_uuid_ids_through() {
        let mut c = cfg();
        c.id_transform = OpenFGAIdTransform::UuidDashes;
        let m = ObjectMapper::from_config(&c);

        assert_eq!(
            m.canonical_object(Kind::Domain, "default").unwrap(),
            "domain:default"
        );
        assert_eq!(
            m.parse_object("domain:default"),
            Some((Kind::Domain, "default".to_string()))
        );
        assert_eq!(
            m.canonical_object(Kind::System, "all").unwrap(),
            "system:all"
        );
    }

    #[test]
    fn empty_type_list_has_no_canonical_object() {
        let mut c = cfg();
        c.system_target_types = vec![];
        let m = ObjectMapper::from_config(&c);
        assert!(matches!(
            m.canonical_object(Kind::System, "all"),
            Err(OpenFGADriverError::NoTypeConfigured("system"))
        ));
    }

    #[test]
    fn kinds_round_trip_through_assignment_type() {
        for t in [
            AssignmentType::UserProject,
            AssignmentType::UserDomain,
            AssignmentType::UserSystem,
            AssignmentType::GroupProject,
            AssignmentType::GroupDomain,
            AssignmentType::GroupSystem,
        ] {
            let (a, tgt) = assignment_type_kinds(&t);
            assert!(a.is_actor());
            assert_eq!(kinds_to_assignment_type(a, tgt), Some(t));
        }
    }

    #[test]
    fn kinds_to_assignment_type_rejects_bad_pairing() {
        assert_eq!(kinds_to_assignment_type(Kind::Project, Kind::User), None);
        assert_eq!(kinds_to_assignment_type(Kind::User, Kind::Group), None);
    }

    #[test]
    fn dedupe_collapses_representation_duplicates() {
        let a = Assignment {
            actor_id: "u1".into(),
            role_id: "r1".into(),
            role_name: None,
            target_id: "p1".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: None,
        };
        let out = dedupe_assignments(vec![a.clone(), a.clone(), a]);
        assert_eq!(out.len(), 1);
    }
}
