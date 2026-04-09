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
use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::debug;

use crate::pb;
use crate::protobuf::api::Response as PbResponse;
use crate::protobuf::api::identity_service_server::IdentityService;
use crate::store_service::StoreService;

#[tonic::async_trait]
impl IdentityService for Arc<StoreService> {
    /// Sets a value for a given key in the distributed store.
    ///
    /// # Arguments
    /// * `request` - Contains the key and value to set
    ///
    /// # Returns
    /// * `Ok(Response)` - Success response after the value is set
    /// * `Err(Status)` - Error status if the set operation fails
    #[tracing::instrument(level = "trace", skip(self))]
    async fn set(
        &self,
        request: Request<pb::api::SetRequest>,
    ) -> Result<Response<PbResponse>, Status> {
        let req = request.into_inner();
        debug!("Processing set request for key: {}", req.key.clone());

        let res = self
            .set_value(req.key.clone(), req.value)
            .await
            .map_err(|e| Status::internal(format!("Failed to write to store: {}", e)))?;

        debug!("Successfully set value for key: {}", req.key);
        Ok(Response::new(res.data))
    }

    /// Gets a value for a given key from the distributed store.
    ///
    /// # Arguments
    /// * `request` - Contains the key to retrieve
    ///
    /// # Returns
    /// * `Ok(Response)` - Success response containing the value
    /// * `Err(Status)` - Error status if the get operation fails
    #[tracing::instrument(level = "trace", skip(self))]
    async fn get(
        &self,
        request: Request<pb::api::GetRequest>,
    ) -> Result<Response<PbResponse>, Status> {
        let req = request.into_inner();
        debug!("Processing get request for key: {}", req.key);

        let value = self
            .get_by_key(&req.key)
            .await
            .map_err(|_| Status::internal(format!("Key not found: {}", req.key)))?
            .map(String::from_utf8)
            .transpose()
            .map_err(|e| Status::internal(format!("error while converting the data, {}", e)))?;

        debug!("Successfully retrieved value for key: {}", req.key);
        Ok(Response::new(PbResponse { value }))
    }
}
