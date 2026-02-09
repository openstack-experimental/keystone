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

use goose::prelude::*;

use crate::Session;

/// Test listing Keystone users.
pub async fn list(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();

    let reqwest_request_builder = user
        .get_request_builder(&GooseMethod::Get, "/v3/users")?
        .header("x-auth-token", &session.token);

    // Add the manually created RequestBuilder and build a GooseRequest object.
    let goose_request = GooseRequest::builder()
        .set_request_builder(reqwest_request_builder)
        .build();

    // Make the actual request.
    user.request(goose_request).await?;

    Ok(())
}
