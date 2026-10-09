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
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use eyre::Result;
use openraft::LogIdOptionExt;
use openraft::async_runtime::AsyncRuntime;
use openraft::async_runtime::WatchReceiver;
use openraft::type_config::TypeConfigExt;
use openraft::type_config::alias::AsyncRuntimeOf;
use tempfile::TempDir;

use tonic::transport::{Channel, ClientTlsConfig, Uri};

use openstack_keystone_config::TlsConfiguration;
use openstack_keystone_distributed_storage::app::{Storage, get_app_server, init_storage};
use openstack_keystone_distributed_storage::config::{
    DistributedStorageConfiguration, KekProvider, RaftTlsConfiguration, config_manager,
};
use openstack_keystone_distributed_storage::network::{
    get_client_tls_config, get_server_tls_config,
};
use openstack_keystone_distributed_storage::protobuf as pb;
use openstack_keystone_distributed_storage::protobuf::raft::cluster_admin_service_client::ClusterAdminServiceClient;
use openstack_keystone_distributed_storage::store::state_machine::meta_key;
use openstack_keystone_distributed_storage::store_command::*;
use openstack_keystone_distributed_storage::{
    ApiStoreError, DataTier, Metadata, StoreDataEnvelope, StoreError,
};
use openstack_keystone_distributed_storage::{StorageApi, TypeConfig};

mod admin;
mod basic;
mod crash;
#[path = "../common/mod.rs"]
mod common;
mod harness;
mod join;
mod kek;
mod quarantine;
mod races;
mod restore;
mod rotation;
