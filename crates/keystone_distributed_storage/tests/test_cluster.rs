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
#![allow(clippy::uninlined_format_args)]
use std::backtrace::Backtrace;
use std::collections::BTreeMap;
use std::panic::PanicHookInfo;
use std::thread;
use std::time::Duration;

use eyre::Result;
use openraft::async_runtime::AsyncRuntime;
use openraft::type_config::TypeConfigExt;
use openraft::type_config::alias::AsyncRuntimeOf;
use tonic::transport::Channel;
use tracing_subscriber::EnvFilter;

use openstack_keystone_distributed_storage::TypeConfig;
use openstack_keystone_distributed_storage::app::start_raft_app;
use openstack_keystone_distributed_storage::protobuf as pb;
use openstack_keystone_distributed_storage::protobuf::api::identity_service_client::IdentityServiceClient;
use openstack_keystone_distributed_storage::protobuf::raft::cluster_admin_service_client::ClusterAdminServiceClient;

pub fn log_panic(panic: &PanicHookInfo) {
    let backtrace = { format!("{:?}", Backtrace::force_capture()) };

    eprintln!("{}", panic);

    if let Some(location) = panic.location() {
        tracing::error!(
            message = %panic,
            backtrace = %backtrace,
            panic.file = location.file(),
            panic.line = location.line(),
            panic.column = location.column(),
        );
        eprintln!(
            "{}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    } else {
        tracing::error!(message = %panic, backtrace = %backtrace);
    }

    eprintln!("{}", backtrace);
}

/// Set up a cluster of 3 nodes.
/// Write to it and read from it.
#[test]
fn test_cluster() {
    TypeConfig::run(test_cluster_inner()).unwrap();
}

async fn test_cluster_inner() -> Result<()> {
    std::panic::set_hook(Box::new(|panic| {
        log_panic(panic);
    }));

    tracing_subscriber::fmt()
        .with_target(true)
        .with_thread_ids(true)
        .with_level(true)
        .with_ansi(false)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // --- Start 3 raft node in 3 threads.

    let _h1 = thread::spawn(|| {
        let d1 = tempfile::TempDir::new().unwrap();
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let x = rt.block_on(start_raft_app(1, get_addr(1), d1.path()));
        println!("raft app exit result: {:?}", x);
    });

    let _h2 = thread::spawn(|| {
        let d2 = tempfile::TempDir::new().unwrap();
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let x = rt.block_on(start_raft_app(2, get_addr(2), d2.path()));
        println!("raft app exit result: {:?}", x);
    });

    let _h3 = thread::spawn(|| {
        let d3 = tempfile::TempDir::new().unwrap();
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let x = rt.block_on(start_raft_app(3, get_addr(3), d3.path()));
        println!("raft app exit result: {:?}", x);
    });

    // Wait for server to start up.
    TypeConfig::sleep(Duration::from_millis(200)).await;

    let mut admin_client1 = new_admin_client(get_addr(1)).await?;

    // --- Initialize the target node as a cluster of only one node.
    //     After init(), the single node cluster will be fully functional.
    println!("=== init single node cluster");
    {
        admin_client1
            .init(pb::raft::InitRequest {
                nodes: vec![new_node(1)],
            })
            .await?;

        let metrics = admin_client1.metrics(()).await?.into_inner();
        println!("=== metrics after init: {:?}", metrics);
    }

    println!(
        "=== Add node 2, 3 to the cluster as learners, to let them start to receive log replication from the leader"
    );
    {
        println!("=== add-learner 2");
        admin_client1
            .add_learner(pb::raft::AddLearnerRequest {
                node: Some(new_node(2)),
            })
            .await?;

        println!("=== add-learner 3");
        admin_client1
            .add_learner(pb::raft::AddLearnerRequest {
                node: Some(new_node(3)),
            })
            .await?;

        let metrics = admin_client1.metrics(()).await?.into_inner();
        println!("=== metrics after add-learner: {:?}", metrics);
        assert_eq!(
            vec![pb::raft::NodeIdSet {
                node_ids: BTreeMap::from([(1, ())]),
            }],
            metrics.membership.clone().unwrap().configs
        );
        assert_eq!(
            BTreeMap::from([(1, new_node(1)), (2, new_node(2)), (3, new_node(3))]),
            metrics.membership.unwrap().nodes
        );
    }

    // --- Turn the two learners to members.
    //     A member node can vote or elect itself as leader.

    println!("=== change-membership to 1,2,3");
    {
        admin_client1
            .change_membership(pb::raft::ChangeMembershipRequest {
                members: vec![1, 2, 3],
                retain: false,
            })
            .await?;

        let metrics = admin_client1.metrics(()).await?.into_inner();
        println!("=== metrics after change-member: {:?}", metrics);
        assert_eq!(
            vec![pb::raft::NodeIdSet {
                node_ids: BTreeMap::from([(1, ()), (2, ()), (3, ())]),
            }],
            metrics.membership.unwrap().configs
        );
    }
    let mut client1 = new_client(get_addr(1)).await?;

    println!("=== write `foo=bar`");
    {
        client1
            .set(pb::api::SetRequest {
                key: "foo".to_string(),
                value: "bar".to_string(),
            })
            .await?;

        // --- Wait for a while to let the replication get done.
        TypeConfig::sleep(Duration::from_millis(1_000)).await;
    }

    println!("=== read `foo` on every node");
    {
        println!("=== read `foo` on node 1");
        {
            let got = client1
                .get(pb::api::GetRequest {
                    key: "foo".to_string(),
                })
                .await?;
            assert_eq!(Some("bar".to_string()), got.into_inner().value);
        }

        println!("=== read `foo` on node 2");
        {
            let mut client2 = new_client(get_addr(2)).await?;
            let got = client2
                .get(pb::api::GetRequest {
                    key: "foo".to_string(),
                })
                .await?;
            assert_eq!(Some("bar".to_string()), got.into_inner().value);
        }

        println!("=== read `foo` on node 3");
        {
            let mut client3 = new_client(get_addr(3)).await?;
            let got = client3
                .get(pb::api::GetRequest {
                    key: "foo".to_string(),
                })
                .await?;
            assert_eq!(Some("bar".to_string()), got.into_inner().value);
        }
    }

    println!("=== Remove node 1,2 by change-membership to {{3}}");
    {
        admin_client1
            .change_membership(pb::raft::ChangeMembershipRequest {
                members: vec![3],
                retain: false,
            })
            .await?;

        TypeConfig::sleep(Duration::from_millis(2_000)).await;

        let metrics = admin_client1.metrics(()).await?.into_inner();
        println!(
            "=== metrics after change-membership to {{3}}: {:?}",
            metrics
        );
        assert_eq!(
            vec![pb::raft::NodeIdSet {
                node_ids: BTreeMap::from([(3, ())]),
            }],
            metrics.membership.unwrap().configs
        );
    }

    Ok(())
}

async fn new_admin_client(
    addr: String,
) -> Result<ClusterAdminServiceClient<Channel>, tonic::transport::Error> {
    let channel = Channel::builder(format!("https://{}", addr).parse().unwrap())
        .connect()
        .await?;
    let client = ClusterAdminServiceClient::new(channel);
    Ok(client)
}

async fn new_client(
    addr: String,
) -> Result<IdentityServiceClient<Channel>, tonic::transport::Error> {
    let channel = Channel::builder(format!("https://{}", addr).parse().unwrap())
        .connect()
        .await?;
    let client = IdentityServiceClient::new(channel);
    Ok(client)
}

fn new_node(node_id: u64) -> pb::raft::Node {
    pb::raft::Node {
        node_id,
        rpc_addr: get_addr(node_id),
    }
}

fn get_addr(node_id: u64) -> String {
    match node_id {
        1 => "127.0.0.1:21001".to_string(),
        2 => "127.0.0.1:21002".to_string(),
        3 => "127.0.0.1:21003".to_string(),
        _ => {
            unreachable!("node_id must be 1, 2, or 3");
        }
    }
}
