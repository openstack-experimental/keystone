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
//! Graceful-shutdown drain of the audit spool (issue #1316).
//!
//! Mirrors the wiring in `keystone::server::startup::audit::init` and
//! `shutdown::await_audit_writer`: events go through the real dispatcher, the
//! token is cancelled while the channels are still open, and the writer
//! `JoinHandle` is awaited. Every dispatched event must end up in the spool.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use openstack_keystone_audit::spool::{run_spool_writer, spool_path};
use openstack_keystone_audit::{
    AuditDispatcher, CadfEvent, CadfEventPayload, Initiator, Observer, SpoolConfig, Target,
};

fn event(dispatcher: &AuditDispatcher) -> CadfEvent {
    CadfEventPayload::new(
        format!("{}:{}", dispatcher.node_id(), Uuid::new_v4()),
        "1.0".to_string(),
        "default".to_string(),
        Uuid::new_v4().to_string(),
        chrono::Utc::now().to_rfc3339(),
        "authenticate".to_string(),
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

fn spawn_writer(
    dir: &std::path::Path,
    dispatcher: &Arc<AuditDispatcher>,
    receivers: openstack_keystone_audit::AuditChannelReceivers,
    cfg: SpoolConfig,
    token: &CancellationToken,
) -> JoinHandle<()> {
    let dir = dir.to_path_buf();
    let node_id = dispatcher.node_id().to_string();
    let spool_bytes = dispatcher.spool_bytes_handle();
    let shutdown = token.clone().cancelled_owned();
    tokio::spawn(async move {
        run_spool_writer(
            receivers.perimeter,
            receivers.critical,
            dir,
            node_id,
            cfg,
            spool_bytes,
            shutdown,
        )
        .await;
    })
}

fn spool_lines(dir: &std::path::Path, node: &str) -> usize {
    std::fs::read_to_string(spool_path(dir, node))
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

#[tokio::test]
async fn shutdown_spools_every_dispatched_event() {
    const CRITICAL: usize = 50;
    const PERIMETER: usize = 200;

    let dir = tempfile::tempdir().expect("tempdir");
    let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
    let (dispatcher, receivers) =
        AuditDispatcher::new("node-1", Uuid::new_v4().to_string(), key, 1);
    let token = CancellationToken::new();
    let writer = spawn_writer(
        dir.path(),
        &dispatcher,
        receivers,
        SpoolConfig::default(),
        &token,
    );

    for _ in 0..CRITICAL {
        dispatcher
            .dispatch_critical(event(&dispatcher))
            .await
            .expect("critical channel alive");
    }
    for _ in 0..PERIMETER {
        dispatcher.dispatch(event(&dispatcher));
    }

    // The dispatcher (and its senders) stays alive, as it does in the server:
    // only the token ends the writer.
    token.cancel();
    tokio::time::timeout(Duration::from_secs(10), writer)
        .await
        .expect("writer stops within the drain budget")
        .expect("writer task did not panic");

    assert_eq!(dispatcher.dropped_count(), 0);
    assert_eq!(spool_lines(dir.path(), "node-1"), CRITICAL + PERIMETER);

    // Channels are closed once the writer is gone: no silent queueing.
    assert!(
        dispatcher
            .dispatch_critical(event(&dispatcher))
            .await
            .is_err()
    );
}
