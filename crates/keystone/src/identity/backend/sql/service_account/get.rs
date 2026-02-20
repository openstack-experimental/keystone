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

use sea_orm::DatabaseConnection;

use super::super::nonlocal_user;
use super::super::user;
use super::super::user_option;
use crate::config::Config;
use crate::identity::{
    IdentityProviderError,
    types::{ServiceAccount, ServiceAccountBuilder},
};

#[tracing::instrument(skip_all)]
pub async fn get<U>(
    conf: &Config,
    db: &DatabaseConnection,
    user_id: U,
) -> Result<Option<ServiceAccount>, IdentityProviderError>
where
    U: AsRef<str>,
{
    let (main_row_handle, nl_user_handle, user_opts_handle) = tokio::join!(
        user::get_main_entry(db, user_id.as_ref()),
        nonlocal_user::get_by_user_id(db, user_id.as_ref()),
        user_option::list_by_user_id(db, user_id.as_ref()),
    );

    let user_opts = user_opts_handle?;
    if !user_opts.is_service_account.is_some_and(|x| x) {
        return Ok(None);
    }

    let mut sa_builder = ServiceAccountBuilder::default();
    if let (Some(main), Some(nl)) = (main_row_handle?, nl_user_handle?) {
        sa_builder.domain_id(main.domain_id);
        let last_activity_cutof_date = conf.security_compliance.get_user_last_activity_cutof_date();
        // TODO: This is the same logic as in the `UserResponseBuilder::merge_user_data`
        // and must be reused.
        sa_builder.enabled(if main.enabled.is_some_and(|val| val) {
            if let (Some(last_active_at), Some(cutoff)) =
                (&main.last_active_at, &last_activity_cutof_date)
            {
                user_opts.ignore_user_inactivity.is_some_and(|val| val) || last_active_at > cutoff
            } else {
                // Either last_active_at or cutoff date empty - user is active
                true
            }
        } else {
            false
        });
        sa_builder.id(main.id);
        sa_builder.name(nl.name);
        return Ok(Some(sa_builder.build()?));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::*;
    use crate::config::Config;
    use crate::identity::backend::sql::nonlocal_user::tests::get_nonlocal_user_mock;
    use crate::identity::backend::sql::user::tests::get_user_mock;
    use crate::identity::backend::sql::user_option::tests::get_user_options_mock;
    use crate::identity::types::UserOptions;

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_user_mock("1")]])
            .append_query_results([vec![get_nonlocal_user_mock("1")]])
            .append_query_results([get_user_options_mock(
                "1",
                &UserOptions {
                    is_service_account: Some(true),
                    ..Default::default()
                },
            )])
            .into_connection();

        let sot = get(&Config::default(), &db, "1")
            .await
            .unwrap()
            .expect("must be something");

        assert_eq!("1", sot.id);
    }
}
