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

use tonic::{Request, Status};

use crate::store_command::{MutationInner, StoreCommand};

/// Role a peer certificate resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    /// Another cluster node: Raft replication, forwarded reads/writes.
    Node,
    /// Human/automation operator: management RPCs.
    Operator,
}

const NODE_ROLE: &str = "node";

#[derive(Debug, Clone)]
enum Mode {
    Spiffe {
        trust_domains: Vec<String>,
        path_prefix: String,
        operator_role: String,
        allowed_peer_svids: Vec<String>,
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
        let role = self.role_of_identity(san)?;
        if allowed.contains(&role) {
            Ok((identity.to_owned(), role))
        } else {
            Err(Status::permission_denied(format!(
                "role {role:?} is not authorised for this RPC"
            )))
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

    /// Map a peer identity string (URI SAN) to a role. Pure; no I/O.
    ///
    /// In SPIFFE mode the role-convention path (`<path_prefix><role>`) takes
    /// precedence over `allowed_peer_svids`: an allow-list entry under the
    /// prefix with an unknown role is denied, and one equal to the operator
    /// path resolves to [`PeerRole::Operator`]. Only entries outside the
    /// prefix resolve (to [`PeerRole::Node`]) via the allow-list.
    pub fn role_of_identity(&self, identity: &str) -> Result<PeerRole, Status> {
        match &self.mode {
            Mode::TlsLegacy => Ok(PeerRole::Node),
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
                role_from_name(role, operator_role)
            }
            Mode::Spiffe {
                trust_domains,
                path_prefix,
                operator_role,
                allowed_peer_svids,
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
                // Role-convention path first, then the exact allow-list.
                if let Some(role) = path
                    .strip_prefix(path_prefix.as_str())
                    .filter(|r| !r.is_empty() && !r.contains('/'))
                {
                    return role_from_name(role, operator_role);
                }
                if allowed_peer_svids.iter().any(|s| s == identity) {
                    return Ok(PeerRole::Node);
                }
                Err(Status::permission_denied(format!(
                    "SPIFFE ID '{identity}' has no authorised storage role"
                )))
            }
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
            },
        }
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

fn role_from_name(role: &str, operator_role: &str) -> Result<PeerRole, Status> {
    if role == NODE_ROLE {
        Ok(PeerRole::Node)
    } else if role == operator_role {
        Ok(PeerRole::Operator)
    } else {
        Err(Status::permission_denied(format!(
            "unknown storage role '{role}'"
        )))
    }
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
                    | MutationInner::SetIndex { .. } => {}
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
}
