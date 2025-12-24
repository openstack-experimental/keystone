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

use crate::db::entity::trust as db_trust;
use crate::trust::backend::error::TrustDatabaseError;
use crate::trust::types::*;
use chrono::DateTime;
use serde_json::Value;
use tracing::error;

mod get;
mod list;

pub use get::get;
pub use list::list;

impl TryFrom<db_trust::Model> for Trust {
    type Error = TrustDatabaseError;

    fn try_from(value: db_trust::Model) -> Result<Self, Self::Error> {
        let mut builder = TrustBuilder::default();
        if let Some(val) = &value.deleted_at {
            builder.deleted_at(val.and_utc());
        }
        if let Some(val) = value.expires_at_int {
            builder.expires_at(
                DateTime::from_timestamp_micros(val)
                    .map(|val| val.to_utc())
                    .ok_or_else(|| Self::Error::ExpirationDateTimeParse {
                        id: value.id.clone(),
                        expires_at: val,
                    })?,
            );
        } else if let Some(val) = value.expires_at {
            builder.expires_at(val.and_utc());
        }
        if let Some(extra) = &value.extra
            && extra != "{}"
        {
            match serde_json::from_str::<Value>(extra) {
                Ok(extras) => {
                    builder.extra(extras);
                }
                Err(e) => {
                    error!("failed to deserialize trust extra: {e}");
                }
            }
        }

        builder.id(value.id);
        builder.impersonation(value.impersonation);
        if let Some(val) = &value.project_id {
            builder.project_id(val);
        }
        if let Some(val) = value.remaining_uses {
            builder.remaining_uses(val);
        }
        if let Some(val) = &value.redelegated_trust_id {
            builder.redelegated_trust_id(val);
        }
        if let Some(val) = value.redelegation_count {
            builder.redelegation_count(val);
        }
        builder.trustor_user_id(value.trustor_user_id);
        builder.trustee_user_id(value.trustee_user_id);
        Ok(builder.build()?)
    }
}

impl TryFrom<&db_trust::Model> for Trust {
    type Error = TrustDatabaseError;

    fn try_from(value: &db_trust::Model) -> Result<Self, Self::Error> {
        Self::try_from(value.clone())
    }
}

#[cfg(test)]
mod tests {

    use crate::db::entity::trust;

    pub fn get_trust_mock<S: AsRef<str>, U1: AsRef<str>, U2: AsRef<str>>(
        id: S,
        trustor_id: U1,
        trustee_id: U2,
    ) -> trust::Model {
        trust::Model {
            id: id.as_ref().into(),
            trustor_user_id: trustor_id.as_ref().into(),
            trustee_user_id: trustee_id.as_ref().into(),
            project_id: Some("pid".into()),
            impersonation: false,
            deleted_at: None,
            expires_at: None,
            remaining_uses: None,
            extra: Some("{}".into()),
            expires_at_int: None,
            redelegated_trust_id: None,
            redelegation_count: None,
        }
    }
}
