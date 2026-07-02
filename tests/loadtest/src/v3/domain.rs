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

/// List all domains (read-heavy scenario transaction).
pub async fn list(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let req = user
        .get_request_builder(&GooseMethod::Get, "/v3/domains")?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder().set_request_builder(req).build();

    user.request(goose_request).await?;
    Ok(())
}
