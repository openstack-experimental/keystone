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

//! Per-site KEK administration (ADR 0045 §11.2).

use std::collections::HashSet;

use openstack_keystone_storage_crypto::SiteEntry;

use super::*;
use crate::store_command::SiteRecord;

impl ClusterAdminServiceImpl {
    pub(super) async fn handle_set_sites(
        &self,
        request: Request<pb::raft::SetSitesRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let actor = require_operator(&request, &self.authz)?;
        self.ensure_leader()?;
        let req = request.into_inner();

        let kek = self.kek.as_site_kek().ok_or_else(|| {
            Status::failed_precondition("SetSites needs kek_provider = \"per_site\"")
        })?;
        if req.sites.is_empty() {
            return Err(Status::invalid_argument("the site list must not be empty"));
        }
        let mut names = HashSet::new();
        for s in &req.sites {
            if s.name.is_empty() || s.name.len() > 255 || s.key_version == 0 {
                return Err(Status::invalid_argument(format!(
                    "site '{}': the name must be 1 to 255 bytes and the key version at least 1",
                    s.name
                )));
            }
            if !names.insert(s.name.as_str()) {
                return Err(Status::invalid_argument(format!(
                    "site '{}' is listed twice",
                    s.name
                )));
            }
        }
        let records: Vec<SiteRecord> = req
            .sites
            .iter()
            .map(|s| SiteRecord {
                name: s.name.clone(),
                public_key_der: s.public_key_der.clone(),
                key_version: s.key_version,
            })
            .collect();

        // Dry run on the leader: the keys must be usable, this site must stay
        // in the list and the current DEK must be re-wrappable, or the apply
        // would leave the other sites with envelopes that exclude them.
        let entries: Vec<SiteEntry> = records.iter().map(SiteEntry::from).collect();
        let (version, wrapped) = self
            .sm
            .current_dek_wrapped()
            .map_err(|e| Status::internal(format!("reading the current DEK: {e}")))?;
        kek.rewrap_for(&entries, &wrapped)
            .await
            .map_err(|e| Status::invalid_argument(format!("the site list is not usable: {e}")))?;

        let sites: Vec<&str> = records.iter().map(|s| s.name.as_str()).collect();
        let details = serde_json::json!({ "sites": sites });
        let cmd = StoreCommand::Transaction(vec![MutationInner::SetSites { sites: records }]);
        let payload =
            pb::api::CommandRequest::try_from(cmd).map_err(|e| Status::internal(e.to_string()))?;
        let write = self
            .raft_node
            .client_write(payload)
            .await
            .map_err(|e| raft_write_status("Raft write failed", e));
        self.audit_outcome("SITES_SET", &actor, version, details, &write);
        write?;
        Ok(Response::new(pb::raft::AdminResponse::default()))
    }

    pub(super) async fn handle_list_sites(
        &self,
        request: Request<()>,
    ) -> Result<Response<pb::raft::ListSitesResponse>, Status> {
        require_operator(&request, &self.authz)?;
        let kek = self.kek.as_site_kek().ok_or_else(|| {
            Status::failed_precondition("ListSites needs kek_provider = \"per_site\"")
        })?;
        let sites = kek
            .registry()
            .list()
            .into_iter()
            .map(|s| pb::raft::Site {
                name: s.name,
                public_key_der: s.public_key_der,
                key_version: s.key_version,
            })
            .collect();
        Ok(Response::new(pb::raft::ListSitesResponse { sites }))
    }
}
