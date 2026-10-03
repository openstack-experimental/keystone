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

//! RFC 5424 syslog sink over TCP, optionally wrapped in TLS (#1375).
//!
//! Each event becomes one syslog message whose `MSG` is the signed CADF JSON
//! line, so a receiver can verify the HMAC exactly as it would from the
//! spool. Messages are framed with octet counting (RFC 6587 §3.4.1), which is
//! safe for payloads containing newlines.
//!
//! A batch is delivered over a fresh connection that is closed afterwards.
//! TCP gives no application-level acknowledgement, so `Ok` means "written and
//! flushed to the peer", and a failure anywhere (connect, TLS handshake,
//! write, close) is returned as a [`SinkError`] so the shipper keeps the
//! segment and retries it: delivery is at-least-once. Every network step is
//! bounded by a timeout, so an unresponsive endpoint cannot block the shipper
//! (and with it shutdown) indefinitely.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::sink::{AuditSink, SinkError};
use crate::types::CadfEvent;

/// Syslog facility 13, "log audit" (RFC 5424 table 1).
const FACILITY_LOG_AUDIT: u8 = 13;
/// Syslog severity 6, "informational".
const SEVERITY_INFORMATIONAL: u8 = 6;

/// Options for [`SyslogSink`].
#[derive(Debug, Clone)]
pub struct SyslogSinkConfig {
    /// `host:port` of the syslog receiver.
    pub endpoint: String,
    /// Wrap the connection in TLS. The server certificate is verified against
    /// `ca_file` when set, otherwise against the system trust store.
    pub tls: bool,
    /// PEM bundle of CA certificates trusted for the receiver.
    pub ca_file: Option<PathBuf>,
    /// `HOSTNAME` field of every message (the Keystone node id).
    pub hostname: String,
    /// `APP-NAME` field of every message.
    pub app_name: String,
    /// Limit for establishing the connection, including the TLS handshake.
    pub connect_timeout: Duration,
    /// Limit for writing and flushing one batch.
    pub write_timeout: Duration,
}

impl SyslogSinkConfig {
    /// A plain-TCP configuration with the default `app_name` and timeouts.
    pub fn new(endpoint: impl Into<String>, hostname: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            tls: false,
            ca_file: None,
            hostname: hostname.into(),
            app_name: "keystone".to_string(),
            connect_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(30),
        }
    }
}

/// Delivers audit events to a syslog receiver (RFC 5424 over TCP/TLS).
pub struct SyslogSink {
    cfg: SyslogSinkConfig,
    tls: Option<(TlsConnector, ServerName<'static>)>,
}

impl SyslogSink {
    /// Build the sink, loading the trust roots and validating the endpoint.
    pub fn new(cfg: SyslogSinkConfig) -> Result<Self, SinkError> {
        let tls = if cfg.tls {
            let host = cfg
                .endpoint
                .rsplit_once(':')
                .map(|(host, _)| host.trim_matches(['[', ']']))
                .ok_or_else(|| {
                    SinkError::Delivery(format!(
                        "syslog endpoint `{}` must be host:port",
                        cfg.endpoint
                    ))
                })?;
            let server_name = ServerName::try_from(host.to_string()).map_err(|e| {
                SinkError::Delivery(format!("invalid syslog TLS server name `{host}`: {e}"))
            })?;
            Some((TlsConnector::from(client_config(&cfg)?), server_name))
        } else {
            None
        };
        Ok(Self { cfg, tls })
    }

    async fn deliver(&self, payload: &[u8]) -> Result<(), SinkError> {
        let tcp = timeout(
            self.cfg.connect_timeout,
            TcpStream::connect(&self.cfg.endpoint),
        )
        .await
        .map_err(|_| {
            SinkError::Delivery(format!("connecting to {} timed out", self.cfg.endpoint))
        })??;
        tcp.set_nodelay(true)?;

        match &self.tls {
            Some((connector, server_name)) => {
                let stream = timeout(
                    self.cfg.connect_timeout,
                    connector.connect(server_name.clone(), tcp),
                )
                .await
                .map_err(|_| SinkError::Delivery("TLS handshake timed out".to_string()))??;
                self.write_all(stream, payload).await
            }
            None => self.write_all(tcp, payload).await,
        }
    }

    async fn write_all<W: AsyncWrite + Unpin>(
        &self,
        mut stream: W,
        payload: &[u8],
    ) -> Result<(), SinkError> {
        timeout(self.cfg.write_timeout, async {
            stream.write_all(payload).await?;
            stream.flush().await?;
            // Closes the TLS session cleanly and sends a TCP FIN so the peer
            // sees a complete stream.
            stream.shutdown().await
        })
        .await
        .map_err(|_| {
            SinkError::Delivery(format!("writing to {} timed out", self.cfg.endpoint))
        })??;
        Ok(())
    }
}

#[async_trait]
impl AuditSink for SyslogSink {
    async fn write_batch(&self, events: &[CadfEvent]) -> Result<(), SinkError> {
        let mut payload = Vec::new();
        for event in events {
            let message = format_message(&self.cfg.hostname, &self.cfg.app_name, event)?;
            // RFC 6587 octet counting: `MSG-LEN SP SYSLOG-MSG`.
            payload.extend_from_slice(message.len().to_string().as_bytes());
            payload.push(b' ');
            payload.extend_from_slice(message.as_bytes());
        }
        self.deliver(&payload).await
    }
}

fn client_config(cfg: &SyslogSinkConfig) -> Result<Arc<rustls::ClientConfig>, SinkError> {
    let mut roots = rustls::RootCertStore::empty();
    match &cfg.ca_file {
        Some(path) => {
            for cert in CertificateDer::pem_file_iter(path).map_err(|e| {
                SinkError::Delivery(format!(
                    "cannot read syslog CA file {}: {e}",
                    path.display()
                ))
            })? {
                let cert = cert.map_err(|e| {
                    SinkError::Delivery(format!("invalid certificate in {}: {e}", path.display()))
                })?;
                roots.add(cert).map_err(|e| {
                    SinkError::Delivery(format!("unusable certificate in {}: {e}", path.display()))
                })?;
            }
            if roots.is_empty() {
                return Err(SinkError::Delivery(format!(
                    "syslog CA file {} contains no certificates",
                    path.display()
                )));
            }
        }
        None => {
            let loaded = rustls_native_certs::load_native_certs();
            // Individual unparsable certificates are tolerated; having no
            // usable root at all is not.
            let (_added, _ignored) = roots.add_parsable_certificates(loaded.certs);
            if roots.is_empty() {
                return Err(SinkError::Delivery(
                    "no system CA certificates available; set `ca_file`".to_string(),
                ));
            }
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| SinkError::Delivery(format!("TLS configuration failed: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Render one RFC 5424 message (without the framing prefix).
fn format_message(hostname: &str, app_name: &str, event: &CadfEvent) -> Result<String, SinkError> {
    let pri = FACILITY_LOG_AUDIT * 8 + SEVERITY_INFORMATIONAL;
    let json = serde_json::to_string(event)?;
    // `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG`
    // PROCID is the process id; MSGID is the CADF action; no structured data.
    Ok(format!(
        "<{pri}>1 {timestamp} {host} {app} {procid} {msgid} - {json}",
        timestamp = header_field(&event.event.event_time),
        host = header_field(hostname),
        app = header_field(app_name),
        procid = std::process::id(),
        msgid = header_field(&event.event.action),
    ))
}

/// Make `value` a legal RFC 5424 header field: printable ASCII without
/// spaces, at most 255 characters, `-` when nothing is left.
fn header_field(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(255)
        .collect();
    if cleaned.is_empty() {
        "-".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditDispatcher, CadfEventPayload, Initiator, Observer, Target};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use uuid::Uuid;

    fn event(dispatcher: &AuditDispatcher, action: &str) -> CadfEvent {
        CadfEventPayload::new(
            format!("{}:{}", dispatcher.node_id(), Uuid::new_v4()),
            "1.0".to_string(),
            Uuid::new_v4().to_string(),
            "2026-10-03T20:00:00+00:00".to_string(),
            action.to_string(),
            "success".to_string(),
            None,
            Initiator::new("unknown".to_string(), None, None, None),
            Target {
                id: "keystone".to_string(),
                type_uri: "service/security/keystone/auth".to_string(),
            },
            Observer {
                node_id: dispatcher.node_id().to_string(),
                id: format!("service/security/keystone/{}", dispatcher.node_id()),
            },
        )
        .sign(dispatcher)
    }

    fn dispatcher() -> Arc<AuditDispatcher> {
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (d, _rx) = AuditDispatcher::new("node-1", Uuid::new_v4().to_string(), key, 1);
        d
    }

    /// Split an octet-counted stream into messages.
    fn parse_frames(mut data: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        while !data.is_empty() {
            let space = data.iter().position(|b| *b == b' ').expect("length prefix");
            let len: usize = std::str::from_utf8(&data[..space])
                .expect("utf8")
                .parse()
                .expect("numeric length");
            let start = space + 1;
            out.push(String::from_utf8(data[start..start + len].to_vec()).expect("utf8"));
            data = &data[start + len..];
        }
        out
    }

    #[test]
    fn message_is_rfc5424_with_signed_json() {
        let d = dispatcher();
        let ev = event(&d, "authenticate");
        let msg = format_message("node-1", "keystone", &ev).unwrap();
        // facility 13 * 8 + severity 6
        assert!(msg.starts_with("<110>1 2026-10-03T20:00:00+00:00 node-1 keystone "));
        assert!(msg.contains(" authenticate - {"));
        let json = &msg[msg.find('{').unwrap()..];
        let parsed: CadfEvent = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.signature(), ev.signature());
    }

    #[test]
    fn header_fields_are_sanitized() {
        assert_eq!(header_field("a b\nc"), "abc");
        assert_eq!(header_field(""), "-");
        assert_eq!(header_field(&"x".repeat(300)).len(), 255);
    }

    #[tokio::test]
    async fn delivers_octet_counted_frames_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            conn.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let d = dispatcher();
        let sink = SyslogSink::new(SyslogSinkConfig::new(addr.to_string(), "node-1")).unwrap();
        sink.write_batch(&[event(&d, "create"), event(&d, "delete")])
            .await
            .expect("delivery succeeds");

        let frames = parse_frames(&receiver.await.unwrap());
        assert_eq!(frames.len(), 2);
        assert!(frames[0].contains(" create - {"));
        assert!(frames[1].contains(" delete - {"));
    }

    #[tokio::test]
    async fn connection_refused_is_a_sink_error() {
        // Bind then drop to obtain a port nothing listens on.
        let addr = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let d = dispatcher();
        let sink = SyslogSink::new(SyslogSinkConfig::new(addr.to_string(), "node-1")).unwrap();
        let err = sink.write_batch(&[event(&d, "create")]).await.unwrap_err();
        assert!(matches!(err, SinkError::Io(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn stuck_receiver_times_out() {
        // The peer accepts but never reads; a payload larger than the socket
        // buffers makes the write block until the timeout fires.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _held = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(conn);
        });

        let d = dispatcher();
        let mut cfg = SyslogSinkConfig::new(addr.to_string(), "node-1");
        cfg.write_timeout = Duration::from_millis(200);
        let sink = SyslogSink::new(cfg).unwrap();
        let batch: Vec<CadfEvent> = (0..40_000).map(|_| event(&d, "create")).collect();
        let err = sink.write_batch(&batch).await.unwrap_err();
        assert!(
            matches!(&err, SinkError::Delivery(m) if m.contains("timed out")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn delivers_over_tls_with_custom_ca() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, cert.pem()).unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der()).unwrap(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let receiver = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(conn).await.unwrap();
            let mut buf = Vec::new();
            tls.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let d = dispatcher();
        let mut cfg = SyslogSinkConfig::new(format!("localhost:{port}"), "node-1");
        cfg.tls = true;
        cfg.ca_file = Some(ca_file);
        let sink = SyslogSink::new(cfg).unwrap();
        sink.write_batch(&[event(&d, "authenticate")])
            .await
            .expect("TLS delivery succeeds");

        let frames = parse_frames(&receiver.await.unwrap());
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains(" authenticate - {"));
    }

    #[tokio::test]
    async fn tls_rejects_untrusted_server() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let trusted = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let rogue = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, trusted.cert.pem()).unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rogue.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::try_from(rogue.signing_key.serialize_der())
                    .unwrap(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(conn).await;
        });

        let d = dispatcher();
        let mut cfg = SyslogSinkConfig::new(format!("localhost:{port}"), "node-1");
        cfg.tls = true;
        cfg.ca_file = Some(ca_file);
        let sink = SyslogSink::new(cfg).unwrap();
        assert!(sink.write_batch(&[event(&d, "create")]).await.is_err());
    }
}
