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
//! # Keystone distributed storage.
//!
//! A distributed storage for OpenStack Keystone backed by Raft and Fjall KV
//! database.

use std::io;
use std::path::Path;
use std::sync::Arc;

use fjall::Database;
use openraft::RaftTypeConfig;

pub mod app;
pub mod grpc;
pub mod network;
mod proto_impl;
mod types;
pub mod store {
    pub mod log_store;
    pub mod state_machine;
}

pub use store::log_store::FjallLogStore;
pub use store::state_machine::FjallStateMachine;
pub use types::StoreError;

pub mod protobuf {
    pub mod api {
        // Import the traits into this specific scope
        use serde::{Deserialize, Serialize};
        tonic::include_proto!("keystone.api");
    }
    pub mod raft {
        // Import the traits into this specific scope
        use serde::{Deserialize, Serialize};
        tonic::include_proto!("keystone.raft");
    }
}
pub use crate::protobuf as pb;

openraft::declare_raft_types!(
    /// Declare the type configuration for example K/V store.
    pub TypeConfig:
        D = pb::api::SetRequest,
        R = pb::api::Response,
        LeaderId = pb::raft::LeaderId,
        Vote = pb::raft::Vote,
        Entry = pb::raft::Entry,
        Node = pb::raft::Node,
        SnapshotData = Vec<u8>,
);

/// Create a pair of `FjallLogStore` and `FjallStateMachine` that are backed by
/// a same fjall db instance.
pub async fn new<C, P: AsRef<Path>>(
    db_path: P,
) -> Result<(FjallLogStore<C>, FjallStateMachine), io::Error>
where
    C: RaftTypeConfig,
{
    let db_path = db_path.as_ref();
    let snapshot_dir = db_path.join("snapshots");
    let db = Database::builder(db_path)
        .open()
        .map_err(|e| io::Error::other(e.to_string()))?;

    let db = Arc::new(db);
    Ok((
        FjallLogStore::new(db.clone())?,
        FjallStateMachine::new(db, snapshot_dir)?,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use openraft::StorageError;
    use openraft::testing::log::StoreBuilder;
    use openraft::testing::log::Suite;
    use openraft::type_config::TypeConfigExt;
    use tempfile::TempDir;
    use tracing_test::traced_test;

    use super::TypeConfig;
    use super::store::log_store::FjallLogStore;
    use super::store::state_machine::FjallStateMachine;

    struct FjallBuilder {}

    impl StoreBuilder<TypeConfig, FjallLogStore<TypeConfig>, Arc<FjallStateMachine>, TempDir>
        for FjallBuilder
    {
        async fn build(
            &self,
        ) -> Result<
            (TempDir, FjallLogStore<TypeConfig>, Arc<FjallStateMachine>),
            StorageError<TypeConfig>,
        > {
            let td =
                TempDir::new().map_err(|e| StorageError::read(TypeConfig::err_from_error(&e)))?;
            let (log_store, sm) = crate::new(td.path())
                .await
                .map_err(|e| StorageError::read(TypeConfig::err_from_error(&e)))?;
            Ok((td, log_store, Arc::new(sm)))
        }
    }

    #[test]
    #[traced_test]
    pub fn test_fjall_store() {
        TypeConfig::run(async {
            Suite::test_all(FjallBuilder {}).await.unwrap();
        });
    }
}
