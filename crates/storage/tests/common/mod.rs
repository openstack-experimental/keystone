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
//! Helpers shared by the cluster integration test binaries
//! (`test_cluster`, `test_pkcs11_cluster`): a throw-away PKI and the
//! sensitive-tier envelope builder. Each binary uses a subset.
#![allow(dead_code)]

use std::net::IpAddr;

use eyre::Result;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use tonic::transport::{Certificate, ClientTlsConfig, Identity};

use openstack_keystone_config::{TlsConfiguration, TlsConfigurationBuilder};
use openstack_keystone_distributed_storage::{DataTier, Metadata, StoreDataEnvelope, StoreError};

/// Envelope carrying `value` (msgpack) at the sensitive tier.
pub fn make_sensitive_env<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<StoreDataEnvelope<Vec<u8>>, StoreError> {
    Ok(StoreDataEnvelope {
        data: rmp_serde::to_vec(value)?,
        metadata: Metadata::with_tier(DataTier::Sensitive),
    })
}

pub fn make_certificates() -> Result<TlsConfiguration> {
    let pki = TestPki::new()?;
    let leaf = pki.leaf(None)?;
    pki.tls_configuration(&leaf)
}

/// Throw-away test CA issuing leaf certificates for cluster nodes and
/// clients.
pub struct TestPki {
    pub ca_pem: String,
    pub issuer: Issuer<'static, KeyPair>,
}

/// PEM-encoded leaf certificate and key issued by a [`TestPki`].
pub struct TestLeaf {
    pub cert_pem: String,
    pub key_pem: String,
}

impl TestPki {
    pub fn new() -> Result<Self> {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];

        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, "CA");
        ca_params.distinguished_name = ca_dn;

        let ca_key = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key)?;
        Ok(Self {
            ca_pem: ca_cert.pem(),
            issuer: Issuer::new(ca_params, ca_key),
        })
    }

    /// Issue a leaf certificate valid for server and client auth on
    /// `127.0.0.1`, optionally carrying `uri_san` as a URI SAN (the only
    /// source a peer role may be derived from).
    pub fn leaf(&self, uri_san: Option<&str>) -> Result<TestLeaf> {
        let mut peer_cert_params = CertificateParams::default();

        // Leaf cert validity must not exceed 30 days (ADR 0016-v2 §4.2,
        // enforced by check_cert_max_validity at storage startup). Bracket
        // the current time with a 1-day buffer on each side so the cert is
        // valid for the lifetime of the test run.
        let now = time::OffsetDateTime::now_utc();
        peer_cert_params.not_before = now - time::Duration::days(1);
        peer_cert_params.not_after = now + time::Duration::days(28);

        let client_ip: IpAddr = "127.0.0.1".parse()?;
        peer_cert_params.subject_alt_names = vec![SanType::IpAddress(client_ip)];
        if let Some(uri) = uri_san {
            peer_cert_params
                .subject_alt_names
                .push(SanType::URI(uri.try_into()?));
        }
        peer_cert_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        peer_cert_params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let peer_key = KeyPair::generate()?;
        let peer_cert = peer_cert_params.signed_by(&peer_key, &self.issuer)?;
        Ok(TestLeaf {
            cert_pem: peer_cert.pem(),
            key_pem: peer_key.serialize_pem(),
        })
    }

    /// Node TLS configuration presenting `leaf` and trusting this CA.
    pub fn tls_configuration(&self, leaf: &TestLeaf) -> Result<TlsConfiguration> {
        Ok(TlsConfigurationBuilder::default()
            .tls_client_ca_content(self.ca_pem.as_bytes().to_vec())
            .tls_cert_content(leaf.cert_pem.as_bytes().to_vec())
            .tls_key_content(leaf.key_pem.as_bytes().to_vec())
            .build()?)
    }

    /// gRPC client TLS configuration presenting `leaf` and trusting this CA.
    pub fn client_tls(&self, leaf: &TestLeaf) -> ClientTlsConfig {
        ClientTlsConfig::new()
            .identity(Identity::from_pem(&leaf.cert_pem, &leaf.key_pem))
            .ca_certificate(Certificate::from_pem(&self.ca_pem))
    }
}
