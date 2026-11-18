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

//! Peer role authorization for the Raft/Storage gRPC surface (issue #1303).

use std::collections::{HashMap, HashSet};

use tonic::{Request, Status};

use crate::store_command::{MutationInner, StoreCommand};

/// Role a peer certificate resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerRole {
    /// Another cluster node: Raft replication, forwarded reads/writes.
    Node,
    /// Human/automation operator: management RPCs.
    Operator,
    /// Raft voter hosted in a core trust domain (ADR 0045 §11.1).
    Voter,
    /// Non-voting Raft learner (evaluation replica storage).
    Learner,
    /// Read-only evaluation replica.
    EvalReplica,
    /// Another authority consuming the inter-authority change feed.
    FeedConsumer,
    /// Mesh proxy attesting proof of possession.
    Proxy,
    /// Member of the cross-authority reservation group.
    ReservationVoter,
}

impl PeerRole {
    /// Static configuration name of the role, if it has one.
    ///
    /// `Node` and `Operator` have no static name: `node` is a separate const
    /// ([`NODE_ROLE`]) and the operator role's name is configurable
    /// (`operator_role`), so neither is a property of the enum.
    pub(crate) const fn name(self) -> Option<&'static str> {
        match self {
            Self::Voter => Some("voter"),
            Self::Learner => Some("learner"),
            Self::EvalReplica => Some("eval-replica"),
            Self::FeedConsumer => Some("feed-consumer"),
            Self::Proxy => Some("proxy"),
            Self::ReservationVoter => Some("reservation-voter"),
            Self::Node | Self::Operator => None,
        }
    }
}

const NODE_ROLE: &str = "node";

/// Roles that only an explicit per-SVID binding can grant (never a path
/// segment), besides the node and operator roles. None of them is authorised
/// on any RPC yet: a peer that holds one is denied everywhere until an RPC
/// lists it explicitly.
const EXTRA_ROLES: [PeerRole; 6] = [
    PeerRole::Voter,
    PeerRole::Learner,
    PeerRole::EvalReplica,
    PeerRole::FeedConsumer,
    PeerRole::Proxy,
    PeerRole::ReservationVoter,
];

/// Resolve a list of `(svid, role names)` bindings into roles per SVID.
///
/// Used for both the remote peers a node accepts and the identities it
/// presents. Every SVID must be a SPIFFE ID in one of `trust_domains`, listed
/// once, with at least one known role and no repeated role.
pub fn resolve_svid_roles(
    bindings: &[crate::config::SvidRoles],
    trust_domains: &[String],
    operator_role: &str,
) -> Result<HashMap<String, Vec<PeerRole>>, String> {
    let mut out: HashMap<String, Vec<PeerRole>> = HashMap::new();
    for b in bindings {
        let rest = b
            .svid
            .strip_prefix("spiffe://")
            .ok_or_else(|| format!("'{}' is not a SPIFFE ID", b.svid))?;
        let domain = rest
            .split_once('/')
            .filter(|(d, p)| !d.is_empty() && !p.is_empty())
            .map(|(d, _)| d)
            .ok_or_else(|| format!("'{}' has no trust domain or no path", b.svid))?;
        if !trust_domains.iter().any(|d| d == domain) {
            return Err(format!(
                "'{}' is in trust domain '{domain}', which is not in trust_domains",
                b.svid
            ));
        }
        if b.roles.is_empty() {
            return Err(format!("'{}' has no roles", b.svid));
        }
        let mut roles = Vec::with_capacity(b.roles.len());
        for name in &b.roles {
            let role = role_from_name(name, operator_role)
                .map_err(|e| format!("'{}': {}", b.svid, e.message()))?;
            if roles.contains(&role) {
                return Err(format!("'{}' lists role '{name}' twice", b.svid));
            }
            roles.push(role);
        }
        if out.insert(b.svid.clone(), roles).is_some() {
            return Err(format!("'{}' is listed twice", b.svid));
        }
    }
    Ok(out)
}

/// Resolve the identities a node presents into the SVID used for each role.
///
/// Same checks as [`resolve_svid_roles`], plus: a role is served by exactly one
/// SVID, and a non-empty list must serve the `node` role (the SVID of Raft
/// replication and of the listener). An empty list resolves to an empty map.
pub fn resolve_identities(
    identities: &[crate::config::SvidRoles],
    trust_domains: &[String],
    operator_role: &str,
) -> Result<HashMap<PeerRole, String>, String> {
    let bound = resolve_svid_roles(identities, trust_domains, operator_role)?;
    let mut by_role: HashMap<PeerRole, String> = HashMap::new();
    // Iterate the configured order so the error names a stable pair.
    for i in identities {
        for role in &bound[&i.svid] {
            if let Some(other) = by_role.insert(*role, i.svid.clone()) {
                return Err(format!(
                    "role {role:?} is served by both '{other}' and '{}'",
                    i.svid
                ));
            }
        }
    }
    if !identities.is_empty() && !by_role.contains_key(&PeerRole::Node) {
        return Err("no identity serves the `node` role".to_string());
    }
    Ok(by_role)
}

#[derive(Debug, Clone)]
enum Mode {
    Spiffe {
        trust_domains: Vec<String>,
        path_prefix: String,
        operator_role: String,
        allowed_peer_svids: Vec<String>,
        /// Explicit roles of remote SVIDs (ADR 0045 §11.1), by full SPIFFE ID.
        /// A listed SVID holds exactly these roles.
        peer_roles: HashMap<String, Vec<PeerRole>>,
        /// Trust domains with at least one `peer_roles` entry (precomputed).
        managed_domains: HashSet<String>,
    },
    /// dev_mode-only: no role derivation, every CA-signed peer accepted.
    TlsLegacy,
    TlsRoles {
        san_prefix: String,
        operator_role: String,
    },
}

/// Resolves peer certificates to [`PeerRole`]s and enforces per-RPC roles.
#[derive(Debug, Clone)]
pub struct PeerAuthz {
    mode: Mode,
}

/// Leaf peer certificate DER, if any.
fn peer_leaf_der<T>(request: &Request<T>) -> Option<Vec<u8>> {
    request
        .peer_certs()
        .and_then(|certs| certs.first().map(|c| c.as_ref().to_vec()))
}

/// First URI SAN of a parsed certificate.
fn first_uri_san(cert: &x509_parser::certificate::X509Certificate<'_>) -> Option<String> {
    cert.subject_alternative_name()
        .ok()
        .flatten()
        .and_then(|san| {
            san.value.general_names.iter().find_map(|n| {
                if let x509_parser::extensions::GeneralName::URI(uri) = n {
                    Some((*uri).to_owned())
                } else {
                    None
                }
            })
        })
}

/// First URI SAN of a DER-encoded certificate.
fn uri_san_from_der(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    first_uri_san(&cert)
}

/// Common name of a DER-encoded certificate (audit use only).
fn cn_from_der(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(str::to_owned)
}

/// Extract the first URI SAN of the peer certificate. No CN fallback: this
/// is the only source role resolution may trust.
pub fn extract_peer_uri_san<T>(request: &Request<T>) -> Option<String> {
    peer_leaf_der(request).and_then(|der| uri_san_from_der(&der))
}

/// Extract the peer TLS identity from the request: prefers SPIFFE URI SAN,
/// falls back to CN, or returns `"unknown"` if no peer cert is present.
///
/// For audit/rate-limit keys only. Never derive a role from this value (the
/// CN is attacker-chosen); use [`extract_peer_uri_san`].
pub fn extract_peer_identity<T>(request: &Request<T>) -> String {
    peer_leaf_der(request)
        .and_then(|der| uri_san_from_der(&der).or_else(|| cn_from_der(&der)))
        .unwrap_or_else(|| "unknown".to_owned())
}

impl PeerAuthz {
    /// Pure core of [`Self::require`]. `uri_san` is the peer's first URI SAN
    /// (the only role source); `identity` is for audit/rate-limit keys.
    pub(crate) fn authorize(
        &self,
        uri_san: Option<&str>,
        identity: &str,
        allowed: &[PeerRole],
    ) -> Result<(String, PeerRole), Status> {
        if allowed.is_empty() {
            return Err(Status::permission_denied(
                "no role is authorised for this RPC",
            ));
        }
        if matches!(self.mode, Mode::TlsLegacy) {
            static WARN_ONCE: std::sync::Once = std::sync::Once::new();
            WARN_ONCE.call_once(|| {
                tracing::warn!(
                    "peer role check skipped: TLS mode without tls_role_san_prefix (dev_mode only)"
                );
            });
            return Ok((identity.to_owned(), allowed[0]));
        }
        let san = uri_san
            .ok_or_else(|| Status::permission_denied("peer certificate carries no URI SAN"))?;
        let roles = self.roles_of_identity(san)?;
        match allowed.iter().find(|a| roles.contains(a)) {
            Some(role) => Ok((identity.to_owned(), *role)),
            None => Err(Status::permission_denied(format!(
                "roles {roles:?} are not authorised for this RPC"
            ))),
        }
    }

    /// Whether peers are authenticated by SPIFFE SVIDs (SPIFFE mode only).
    pub fn is_spiffe(&self) -> bool {
        matches!(self.mode, Mode::Spiffe { .. })
    }

    /// Enforce that the caller holds one of `allowed`. Returns identity+role.
    ///
    /// The role is derived from the first URI SAN only, never the CN. In
    /// `TlsLegacy` (dev_mode) mode the role is NOT verified: the first
    /// allowed role is returned nominally and any CA-signed peer passes.
    pub fn require<T>(
        &self,
        request: &Request<T>,
        allowed: &[PeerRole],
    ) -> Result<(String, PeerRole), Status> {
        let der = peer_leaf_der(request);
        let uri_san = der.as_deref().and_then(uri_san_from_der);
        let identity = uri_san
            .clone()
            .or_else(|| der.as_deref().and_then(cn_from_der))
            .unwrap_or_else(|| "unknown".to_owned());
        self.authorize(uri_san.as_deref(), &identity, allowed)
    }

    /// Map a peer identity string (URI SAN) to its roles. Pure; no I/O.
    ///
    /// In SPIFFE mode an SVID listed in `peers` holds exactly the roles bound
    /// to it. Otherwise the role-convention path (`<path_prefix><role>`)
    /// resolves `node` and the operator role only (any other role needs an
    /// explicit binding, so a path alone can never claim it), and an
    /// `allowed_peer_svids` entry outside the prefix resolves to `node`.
    pub fn roles_of_identity(&self, identity: &str) -> Result<Vec<PeerRole>, Status> {
        match &self.mode {
            Mode::TlsLegacy => Ok(vec![PeerRole::Node]),
            Mode::TlsRoles {
                san_prefix,
                operator_role,
            } => {
                let role = identity
                    .strip_prefix(san_prefix.as_str())
                    .filter(|r| !r.is_empty() && !r.contains('/'))
                    .ok_or_else(|| {
                        Status::permission_denied(
                            "peer certificate carries no recognised storage role SAN",
                        )
                    })?;
                // Only `node` and the operator role may come from a name; the
                // other roles need an explicit per-SVID binding.
                Ok(vec![basic_role(role, operator_role).ok_or_else(|| {
                    Status::permission_denied(format!(
                        "storage role '{role}' cannot be claimed by certificate name"
                    ))
                })?])
            }
            Mode::Spiffe {
                trust_domains,
                path_prefix,
                operator_role,
                allowed_peer_svids,
                peer_roles,
                managed_domains,
            } => {
                let rest = identity.strip_prefix("spiffe://").ok_or_else(|| {
                    Status::permission_denied("peer identity is not a SPIFFE URI")
                })?;
                let split = rest.find('/').ok_or_else(|| {
                    Status::permission_denied("SPIFFE ID is missing a path component")
                })?;
                let (domain, path) = rest.split_at(split);
                if !trust_domains.iter().any(|d| d == domain) {
                    return Err(Status::permission_denied(format!(
                        "SPIFFE trust domain '{domain}' is not allowed"
                    )));
                }
                if let Some(roles) = peer_roles.get(identity) {
                    return Ok(roles.clone());
                }
                // A trust domain with explicit bindings is managed by them
                // alone: a path must not claim `node` or the operator role
                // there, or a compromised registrar of that domain could mint
                // one. The exact allow-list below still applies.
                let managed = managed_domains.contains(domain);
                // Role-convention path first, then the exact allow-list.
                if let Some(role) = path
                    .strip_prefix(path_prefix.as_str())
                    .filter(|r| !managed && !r.is_empty() && !r.contains('/'))
                {
                    let role = role_from_name(role, operator_role)?;
                    if !matches!(role, PeerRole::Node | PeerRole::Operator) {
                        return Err(Status::permission_denied(format!(
                            "role {role:?} cannot be claimed by SPIFFE path; bind it to the SVID in `peers`"
                        )));
                    }
                    return Ok(vec![role]);
                }
                if allowed_peer_svids.iter().any(|s| s == identity) {
                    return Ok(vec![PeerRole::Node]);
                }
                Err(Status::permission_denied(format!(
                    "SPIFFE ID '{identity}' has no authorised storage role"
                )))
            }
        }
    }

    /// Test helper: the single role of an identity that resolves to one.
    #[cfg(test)]
    pub(crate) fn role_of_identity(&self, identity: &str) -> Result<PeerRole, Status> {
        let roles = self.roles_of_identity(identity)?;
        match roles.as_slice() {
            [r] => Ok(*r),
            _ => Err(Status::internal("identity holds several roles")),
        }
    }

    /// SPIFFE mode: roles derive from the SPIFFE ID path.
    pub fn spiffe(
        trust_domains: Vec<String>,
        path_prefix: String,
        operator_role: String,
        allowed_peer_svids: Vec<String>,
    ) -> Self {
        Self {
            mode: Mode::Spiffe {
                trust_domains,
                path_prefix,
                operator_role,
                allowed_peer_svids,
                peer_roles: HashMap::new(),
                managed_domains: HashSet::new(),
            },
        }
    }

    /// Bind explicit roles to remote SVIDs (see [`resolve_svid_roles`]).
    /// No-op outside SPIFFE mode.
    pub fn with_peer_roles(mut self, roles: HashMap<String, Vec<PeerRole>>) -> Self {
        if let Mode::Spiffe {
            peer_roles,
            managed_domains,
            ..
        } = &mut self.mode
        {
            *managed_domains = roles
                .keys()
                .filter_map(|k| k.strip_prefix("spiffe://")?.split_once('/'))
                .map(|(d, _)| d.to_owned())
                .collect();
            *peer_roles = roles;
        }
        self
    }

    /// Legacy permissive TLS mode (dev_mode only): no role checks.
    ///
    /// The role returned by [`Self::require`] in this mode is NOT verified;
    /// it is nominally the first allowed role.
    pub fn tls_legacy() -> Self {
        Self {
            mode: Mode::TlsLegacy,
        }
    }

    /// TLS mode: roles derive from a URI SAN with the given prefix.
    pub fn tls_roles(san_prefix: String) -> Self {
        Self {
            mode: Mode::TlsRoles {
                san_prefix,
                operator_role: "storage-operator".into(),
            },
        }
    }
}

/// The roles a name alone may claim: `node` and the operator role.
fn basic_role(role: &str, operator_role: &str) -> Option<PeerRole> {
    if role == NODE_ROLE {
        Some(PeerRole::Node)
    } else if role == operator_role {
        Some(PeerRole::Operator)
    } else {
        None
    }
}

/// Whether `name` is a role that only an explicit binding can grant.
pub fn is_extra_role_name(name: &str) -> bool {
    EXTRA_ROLES.iter().any(|r| r.name() == Some(name))
}

/// Any known role by name; for parsing explicit bindings only.
fn role_from_name(role: &str, operator_role: &str) -> Result<PeerRole, Status> {
    basic_role(role, operator_role)
        .or_else(|| EXTRA_ROLES.iter().find(|r| r.name() == Some(role)).copied())
        .ok_or_else(|| Status::permission_denied(format!("unknown storage role '{role}'")))
}

/// `command` is a data-plane RPC: only plain data mutations may travel it.
/// Admin mutations and restore commands are proposed in-process only.
pub fn ensure_data_command(cmd: &StoreCommand) -> Result<(), Status> {
    match cmd {
        // An empty transaction is a no-op and is accepted.
        StoreCommand::Transaction(muts) => {
            for m in muts {
                match m {
                    MutationInner::Set { .. }
                    | MutationInner::Remove { .. }
                    | MutationInner::RemoveIndex { .. }
                    | MutationInner::CreateIfAbsent { .. }
                    | MutationInner::SetIndex { .. }
                    // Drivers emit feed events beside their writes; the
                    // state machine checks kind and tier.
                    | MutationInner::Emit { .. }
                    // Proposed by the leader's cleanup task; a request
                    // forwarded after a leader change arrives here. The
                    // state machine enforces the prefix allow-list.
                    | MutationInner::DropKeyspace { .. } => {}
                    _ => {
                        return Err(Status::permission_denied(
                            "mutation is not permitted on the data-plane command RPC",
                        ));
                    }
                }
            }
            Ok(())
        }
        _ => Err(Status::permission_denied(
            "command is not permitted on the data-plane command RPC",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der_with(sans: Vec<rcgen::SanType>, cn: Option<&str>) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = sans;
        params.distinguished_name = rcgen::DistinguishedName::new();
        if let Some(cn) = cn {
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, cn);
        }
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn uri_san_from_der_cn_only_is_none() {
        let der = der_with(vec![], Some("spiffe://example.org/keystone/storage/node"));
        assert_eq!(uri_san_from_der(&der), None);
        assert_eq!(
            cn_from_der(&der).as_deref(),
            Some("spiffe://example.org/keystone/storage/node")
        );
    }

    #[test]
    fn uri_san_from_der_returns_uri() {
        let uri = "spiffe://example.org/keystone/storage/node";
        let der = der_with(
            vec![rcgen::SanType::URI(uri.try_into().unwrap())],
            Some("cn"),
        );
        assert_eq!(uri_san_from_der(&der).as_deref(), Some(uri));
    }

    #[test]
    fn uri_san_from_der_dns_san_and_cn_is_none() {
        let der = der_with(
            vec![rcgen::SanType::DnsName(
                "node.example.org".try_into().unwrap(),
            )],
            Some("cn"),
        );
        assert_eq!(uri_san_from_der(&der), None);
    }

    #[test]
    fn uri_san_from_der_garbage_is_none() {
        assert_eq!(uri_san_from_der(&[0xff, 0x00]), None);
    }

    fn spiffe(allowed: &[&str]) -> PeerAuthz {
        PeerAuthz::spiffe(
            vec!["example.org".into()],
            "/keystone/storage/".into(),
            "storage-operator".into(),
            allowed.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn node_role_by_path() {
        let a = spiffe(&[]);
        assert_eq!(
            a.role_of_identity("spiffe://example.org/keystone/storage/node")
                .unwrap(),
            PeerRole::Node
        );
    }

    #[test]
    fn operator_role_by_path() {
        let a = spiffe(&[]);
        assert_eq!(
            a.role_of_identity("spiffe://example.org/keystone/storage/storage-operator")
                .unwrap(),
            PeerRole::Operator
        );
    }

    #[test]
    fn allowed_peer_svid_is_node() {
        let a = spiffe(&["spiffe://example.org/ns/default/sa/keystone"]);
        assert_eq!(
            a.role_of_identity("spiffe://example.org/ns/default/sa/keystone")
                .unwrap(),
            PeerRole::Node
        );
    }

    #[test]
    fn ns_svid_not_in_allow_list_rejected() {
        let a = spiffe(&[]);
        let e = a
            .role_of_identity("spiffe://example.org/ns/default/sa/other")
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn unknown_storage_role_rejected() {
        let a = spiffe(&[]);
        assert!(
            a.role_of_identity("spiffe://example.org/keystone/storage/backup")
                .is_err()
        );
    }

    #[test]
    fn foreign_trust_domain_rejected() {
        let a = spiffe(&[]);
        assert!(
            a.role_of_identity("spiffe://evil.org/keystone/storage/node")
                .is_err()
        );
    }

    #[test]
    fn tls_roles_by_san_prefix() {
        let a = PeerAuthz::tls_roles("spiffe://keystone/storage/".into());
        assert_eq!(
            a.role_of_identity("spiffe://keystone/storage/node")
                .unwrap(),
            PeerRole::Node
        );
        assert_eq!(
            a.role_of_identity("spiffe://keystone/storage/storage-operator")
                .unwrap(),
            PeerRole::Operator
        );
        assert!(a.role_of_identity("CN=whatever").is_err());
    }

    #[test]
    fn tls_roles_cannot_claim_extra_roles() {
        let a = PeerAuthz::tls_roles("spiffe://keystone/storage/".into());
        for role in EXTRA_ROLES {
            let name = role.name().unwrap();
            assert!(
                a.role_of_identity(&format!("spiffe://keystone/storage/{name}"))
                    .is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn is_spiffe_only_in_spiffe_mode() {
        assert!(spiffe(&[]).is_spiffe());
        assert!(!PeerAuthz::tls_roles("spiffe://keystone/storage/".into()).is_spiffe());
        assert!(!PeerAuthz::tls_legacy().is_spiffe());
    }

    #[test]
    fn require_without_identity_denied() {
        // Request carries no peer certs: identity "unknown".
        let a = spiffe(&[]);
        let req = tonic::Request::new(());
        let e = a.require(&req, &[PeerRole::Node]).unwrap_err();
        assert_eq!(e.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn legacy_tls_allows_without_identity() {
        let a = PeerAuthz::tls_legacy();
        let req = tonic::Request::new(());
        assert!(a.require(&req, &[PeerRole::Node]).is_ok());
    }

    const NODE_SAN: &str = "spiffe://example.org/keystone/storage/node";
    const OP_SAN: &str = "spiffe://example.org/keystone/storage/storage-operator";

    fn code(r: Result<(String, PeerRole), Status>) -> tonic::Code {
        r.unwrap_err().code()
    }

    #[test]
    fn authorize_node_vs_operator_only_denied() {
        let a = spiffe(&[]);
        let r = a.authorize(Some(NODE_SAN), NODE_SAN, &[PeerRole::Operator]);
        assert_eq!(code(r), tonic::Code::PermissionDenied);
    }

    #[test]
    fn authorize_operator_vs_node_only_denied() {
        let a = spiffe(&[]);
        let r = a.authorize(Some(OP_SAN), OP_SAN, &[PeerRole::Node]);
        assert_eq!(code(r), tonic::Code::PermissionDenied);
    }

    #[test]
    fn authorize_operator_vs_node_or_operator_ok() {
        let a = spiffe(&[]);
        let (id, role) = a
            .authorize(Some(OP_SAN), OP_SAN, &[PeerRole::Node, PeerRole::Operator])
            .unwrap();
        assert_eq!(id, OP_SAN);
        assert_eq!(role, PeerRole::Operator);
    }

    #[test]
    fn authorize_ignores_cn_shaped_identity_without_san() {
        // A cert without URI SAN whose CN looks like an operator SPIFFE ID
        // must never resolve to a role.
        let a = spiffe(&[]);
        let r = a.authorize(None, OP_SAN, &[PeerRole::Operator, PeerRole::Node]);
        assert_eq!(code(r), tonic::Code::PermissionDenied);

        let t = PeerAuthz::tls_roles("spiffe://keystone/storage/".into());
        let r = t.authorize(
            None,
            "spiffe://keystone/storage/storage-operator",
            &[PeerRole::Operator],
        );
        assert_eq!(code(r), tonic::Code::PermissionDenied);
    }

    #[test]
    fn authorize_with_san_resolves_role() {
        let t = PeerAuthz::tls_roles("spiffe://keystone/storage/".into());
        let san = "spiffe://keystone/storage/storage-operator";
        let (_, role) = t.authorize(Some(san), san, &[PeerRole::Operator]).unwrap();
        assert_eq!(role, PeerRole::Operator);
    }

    #[test]
    fn authorize_empty_allowed_denied_in_all_modes() {
        let s = spiffe(&[]);
        assert_eq!(
            code(s.authorize(Some(NODE_SAN), NODE_SAN, &[])),
            tonic::Code::PermissionDenied
        );
        let t = PeerAuthz::tls_roles("spiffe://keystone/storage/".into());
        assert_eq!(
            code(t.authorize(None, "x", &[])),
            tonic::Code::PermissionDenied
        );
        let l = PeerAuthz::tls_legacy();
        assert_eq!(
            code(l.authorize(None, "unknown", &[])),
            tonic::Code::PermissionDenied
        );
    }

    #[test]
    fn authorize_legacy_nominal_role_is_first_allowed() {
        let l = PeerAuthz::tls_legacy();
        let (_, role) = l
            .authorize(None, "unknown", &[PeerRole::Operator, PeerRole::Node])
            .unwrap();
        assert_eq!(role, PeerRole::Operator);
    }

    #[test]
    fn spiffe_trailing_slash_nested_and_empty_role_rejected() {
        let a = spiffe(&[]);
        for id in [
            "spiffe://example.org/keystone/storage/node/",
            "spiffe://example.org/keystone/storage/x/node",
            "spiffe://example.org/keystone/storage/",
        ] {
            assert!(a.role_of_identity(id).is_err(), "{id} must be rejected");
        }
    }

    #[test]
    fn spiffe_mode_rejects_non_spiffe_identity() {
        let a = spiffe(&[]);
        assert!(a.role_of_identity("CN=node").is_err());
        assert!(
            a.role_of_identity("https://example.org/keystone/storage/node")
                .is_err()
        );
    }

    #[test]
    fn tls_roles_extra_segment_rejected() {
        let a = PeerAuthz::tls_roles("spiffe://keystone/storage/".into());
        assert!(
            a.role_of_identity("spiffe://keystone/storage/node/extra")
                .is_err()
        );
        assert!(a.role_of_identity("spiffe://keystone/storage/").is_err());
    }

    #[test]
    fn allow_list_entry_under_prefix_with_unknown_role_denied() {
        let id = "spiffe://example.org/keystone/storage/backup";
        let a = spiffe(&[id]);
        assert!(a.role_of_identity(id).is_err());
    }

    #[test]
    fn allow_list_entry_equal_to_operator_path_is_operator() {
        let a = spiffe(&[OP_SAN]);
        assert_eq!(a.role_of_identity(OP_SAN).unwrap(), PeerRole::Operator);
    }

    #[test]
    fn command_filter_allows_set_and_create_if_absent() {
        let ok = StoreCommand::Transaction(vec![
            MutationInner::Set {
                cipher: vec![1],
                expected_revision: None,
                key: b"k".to_vec(),
                keyspace: "data".into(),
                metadata: Default::default(),
                tier: 1,
            },
            MutationInner::CreateIfAbsent {
                cipher: vec![1],
                key: b"k2".to_vec(),
                keyspace: "data".into(),
                metadata: Default::default(),
                tier: 1,
            },
        ]);
        assert!(ensure_data_command(&ok).is_ok());
    }

    #[test]
    fn command_filter_allows_keyspace_drop() {
        // The state machine enforces the prefix allow-list; the data-plane
        // filter must let a forwarded cleanup proposal through after a
        // leader change.
        let ok = StoreCommand::Transaction(vec![MutationInner::DropKeyspace {
            keyspace: "single_use_totp_1".into(),
        }]);
        assert!(ensure_data_command(&ok).is_ok());
    }

    #[test]
    fn command_filter_accepts_empty_transaction() {
        // An empty transaction is a no-op; accepted by design.
        assert!(ensure_data_command(&StoreCommand::Transaction(vec![])).is_ok());
    }

    fn denied(cmd: StoreCommand) {
        let e = ensure_data_command(&cmd).unwrap_err();
        assert_eq!(e.code(), tonic::Code::PermissionDenied);
    }

    fn remove() -> MutationInner {
        MutationInner::Remove {
            key: b"k".to_vec(),
            keyspace: "data".into(),
            expected_revision: None,
        }
    }

    #[test]
    fn command_filter_allows_data_mutations_only() {
        let ok = StoreCommand::Transaction(vec![remove()]);
        assert!(ensure_data_command(&ok).is_ok());

        denied(StoreCommand::Transaction(vec![
            MutationInner::ClearQuarantine {
                partition: "data".into(),
            },
        ]));
        denied(StoreCommand::Transaction(vec![MutationInner::Quarantine {
            node_id: 1,
            partition: "data".into(),
        }]));
        denied(StoreCommand::RestoreAbort {
            restore_id: "r".into(),
        });
    }

    #[test]
    fn command_filter_allows_index_mutations() {
        let ok = StoreCommand::Transaction(vec![
            MutationInner::SetIndex { key: b"k".to_vec() },
            MutationInner::RemoveIndex { key: b"k".to_vec() },
        ]);
        assert!(ensure_data_command(&ok).is_ok());
    }

    #[test]
    fn command_filter_rejects_admin_mutations() {
        denied(StoreCommand::Transaction(vec![MutationInner::InstallDek {
            wrapped_dek: vec![0; 4],
            dek_version: 2,
            is_emergency: false,
        }]));
        denied(StoreCommand::Transaction(vec![
            MutationInner::CreatePendingRotation {
                rotation_id: "r".into(),
                wrapped_dek: vec![0; 4],
                dek_version: 2,
                expires_at: 0,
                initiator: "i".into(),
            },
        ]));
        denied(StoreCommand::Transaction(vec![
            MutationInner::ConfirmPendingRotation {
                rotation_id: "r".into(),
                confirmer: "c".into(),
            },
        ]));
        denied(StoreCommand::Transaction(vec![
            MutationInner::AbortPendingRotation {
                rotation_id: "r".into(),
            },
        ]));
    }

    #[test]
    fn command_filter_rejects_restore_commands() {
        denied(StoreCommand::RestoreChunk {
            restore_id: "r".into(),
            seq: 0,
            data: vec![1, 2, 3],
        });
        denied(StoreCommand::RestoreApply {
            restore_id: "r".into(),
            chunks: 1,
            total_len: 3,
        });
    }

    #[test]
    fn command_filter_rejects_mixed_transaction() {
        denied(StoreCommand::Transaction(vec![
            remove(),
            MutationInner::ClearQuarantine {
                partition: "data".into(),
            },
        ]));
    }

    use crate::config::SvidRoles;

    fn bind(entries: &[(&str, &[&str])]) -> Vec<SvidRoles> {
        entries
            .iter()
            .map(|(svid, roles)| SvidRoles {
                svid: svid.to_string(),
                roles: roles.iter().map(|r| r.to_string()).collect(),
            })
            .collect()
    }

    fn peers(entries: &[(&str, &[&str])]) -> HashMap<String, Vec<PeerRole>> {
        resolve_svid_roles(
            &bind(entries),
            &["core.org".to_string(), "eval.org".to_string()],
            "storage-operator",
        )
        .unwrap()
    }

    fn mesh(entries: &[(&str, &[&str])]) -> PeerAuthz {
        PeerAuthz::spiffe(
            vec!["core.org".into(), "eval.org".into()],
            "/keystone/storage/".into(),
            "storage-operator".into(),
            vec![],
        )
        .with_peer_roles(peers(entries))
    }

    #[test]
    fn extra_roles_cannot_be_claimed_by_path() {
        let a = spiffe(&[]);
        for role in EXTRA_ROLES {
            let Some(name) = role.name() else {
                continue;
            };
            let id = format!("spiffe://example.org/keystone/storage/{name}");
            assert!(a.roles_of_identity(&id).is_err(), "{name}");
        }
    }

    #[test]
    fn bound_svid_holds_all_its_roles() {
        let svid = "spiffe://core.org/ns/ks/sa/node-1";
        let a = mesh(&[(svid, &["node", "voter"])]);
        assert_eq!(
            a.roles_of_identity(svid).unwrap(),
            vec![PeerRole::Node, PeerRole::Voter]
        );
        // Either role authorises an RPC; the matching allowed role is returned.
        let (_, r) = a.authorize(Some(svid), svid, &[PeerRole::Voter]).unwrap();
        assert_eq!(r, PeerRole::Voter);
        let (_, r) = a
            .authorize(Some(svid), svid, &[PeerRole::Operator, PeerRole::Node])
            .unwrap();
        assert_eq!(r, PeerRole::Node);
        assert!(a.authorize(Some(svid), svid, &[PeerRole::Learner]).is_err());
    }

    #[test]
    fn same_domain_peers_get_different_roles() {
        let a = mesh(&[
            ("spiffe://core.org/ns/ks/sa/node-1", &["node", "voter"]),
            ("spiffe://core.org/ns/ks/sa/node-2", &["node"]),
        ]);
        assert_eq!(
            a.roles_of_identity("spiffe://core.org/ns/ks/sa/node-1")
                .unwrap(),
            vec![PeerRole::Node, PeerRole::Voter]
        );
        assert_eq!(
            a.roles_of_identity("spiffe://core.org/ns/ks/sa/node-2")
                .unwrap(),
            vec![PeerRole::Node]
        );
        // Not listed, outside the convention and the allow-list.
        assert!(
            a.roles_of_identity("spiffe://core.org/ns/ks/sa/node-3")
                .is_err()
        );
    }

    #[test]
    fn binding_overrides_the_path_convention() {
        // The path says `node`, the binding says `learner`: the binding wins.
        let svid = "spiffe://eval.org/keystone/storage/node";
        let a = mesh(&[(svid, &["learner"])]);
        assert_eq!(a.roles_of_identity(svid).unwrap(), vec![PeerRole::Learner]);
        // A domain without bindings keeps the convention.
        assert_eq!(
            a.roles_of_identity("spiffe://core.org/keystone/storage/node")
                .unwrap(),
            vec![PeerRole::Node]
        );
    }

    #[test]
    fn bound_domain_rejects_path_claimed_roles() {
        let a = mesh(&[("spiffe://eval.org/ns/ks/sa/replica", &["learner"])]);
        // eval.org has a binding: a path can claim neither node nor operator.
        for role in ["node", "storage-operator"] {
            let id = format!("spiffe://eval.org/keystone/storage/{role}");
            assert!(a.roles_of_identity(&id).is_err(), "{role}");
        }
        // core.org has none: the convention still applies there.
        assert_eq!(
            a.roles_of_identity("spiffe://core.org/keystone/storage/node")
                .unwrap(),
            vec![PeerRole::Node]
        );
    }

    #[test]
    fn binding_is_per_full_svid_not_per_path() {
        let a = mesh(&[("spiffe://core.org/ns/ks/sa/n", &["voter"])]);
        assert!(a.roles_of_identity("spiffe://eval.org/ns/ks/sa/n").is_err());
    }

    #[test]
    fn resolve_svid_roles_rejects_bad_entries() {
        let tds = ["core.org".to_string()];
        let bad = |svid: &str, roles: &[&str]| {
            resolve_svid_roles(&bind(&[(svid, roles)]), &tds, "storage-operator")
        };
        assert!(bad("core.org/x", &["node"]).is_err());
        assert!(bad("spiffe://core.org", &["node"]).is_err());
        assert!(bad("spiffe://core.org/", &["node"]).is_err());
        assert!(bad("spiffe://other.org/x", &["node"]).is_err());
        assert!(bad("spiffe://core.org/x", &[]).is_err());
        assert!(bad("spiffe://core.org/x", &["bogus"]).is_err());
        assert!(bad("spiffe://core.org/x", &["node", "node"]).is_err());
        assert!(bad("spiffe://core.org/x", &["node", "voter"]).is_ok());
        let dup = bind(&[
            ("spiffe://core.org/x", &["node"]),
            ("spiffe://core.org/x", &["voter"]),
        ]);
        assert!(resolve_svid_roles(&dup, &tds, "storage-operator").is_err());
    }

    #[test]
    fn identities_serve_each_role_once() {
        let tds = ["core.org".to_string()];
        let ok = bind(&[
            ("spiffe://core.org/a", &["node", "voter"]),
            ("spiffe://core.org/b", &["reservation-voter"]),
        ]);
        let m = resolve_identities(&ok, &tds, "storage-operator").unwrap();
        assert_eq!(m[&PeerRole::Voter], "spiffe://core.org/a");
        assert_eq!(m[&PeerRole::ReservationVoter], "spiffe://core.org/b");

        let twice = bind(&[
            ("spiffe://core.org/a", &["node"]),
            ("spiffe://core.org/b", &["node"]),
        ]);
        assert!(resolve_identities(&twice, &tds, "storage-operator").is_err());

        let no_node = bind(&[("spiffe://core.org/a", &["voter"])]);
        assert!(resolve_identities(&no_node, &tds, "storage-operator").is_err());
        assert!(
            resolve_identities(&[], &tds, "storage-operator")
                .unwrap()
                .is_empty()
        );
    }
}
