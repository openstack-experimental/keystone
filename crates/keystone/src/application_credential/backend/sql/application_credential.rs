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
//! Role assignment database backend.

use chrono::DateTime;

use crate::application_credential::ApplicationCredentialProviderError;
use crate::application_credential::types::*;
use crate::db::entity::{
    access_rule as db_access_rule, application_credential as db_application_credential,
};

mod create;
mod get;
mod list;

pub use create::create;
pub use get::get;
pub use list::list;

impl TryFrom<db_application_credential::Model> for ApplicationCredentialBuilder {
    type Error = ApplicationCredentialProviderError;

    fn try_from(value: db_application_credential::Model) -> Result<Self, Self::Error> {
        let mut builder = ApplicationCredentialBuilder::default();
        builder.id(value.id.clone());
        builder.name(value.name);
        builder.user_id(value.user_id);
        if let Some(val) = &value.description {
            builder.description(val);
        }
        if let Some(val) = &value.project_id {
            builder.project_id(val);
        }
        if let Some(val) = value.unrestricted {
            builder.unrestricted(val);
        }
        if let Some(val) = value.expires_at {
            builder.expires_at(
                DateTime::from_timestamp_micros(val)
                    .map(|val| val.to_utc())
                    .ok_or_else(|| Self::Error::ExpirationDateTimeParse {
                        id: value.id,
                        expires_at: val,
                    })?,
            );
        }
        Ok(builder)
    }
}

impl TryFrom<db_application_credential::Model> for ApplicationCredentialCreateResponseBuilder {
    type Error = ApplicationCredentialProviderError;

    fn try_from(value: db_application_credential::Model) -> Result<Self, Self::Error> {
        let mut builder = ApplicationCredentialCreateResponseBuilder::default();
        builder.id(value.id.clone());
        builder.name(value.name);
        builder.user_id(value.user_id);
        if let Some(val) = &value.description {
            builder.description(val);
        }
        if let Some(val) = &value.project_id {
            builder.project_id(val);
        }
        if let Some(val) = value.unrestricted {
            builder.unrestricted(val);
        }
        if let Some(val) = value.expires_at {
            builder.expires_at(
                DateTime::from_timestamp_micros(val)
                    .map(|val| val.to_utc())
                    .ok_or_else(|| Self::Error::ExpirationDateTimeParse {
                        id: value.id,
                        expires_at: val,
                    })?,
            );
        }
        Ok(builder)
    }
}

impl TryFrom<&db_application_credential::Model> for ApplicationCredentialBuilder {
    type Error = ApplicationCredentialProviderError;

    fn try_from(value: &db_application_credential::Model) -> Result<Self, Self::Error> {
        ApplicationCredentialBuilder::try_from(value.clone())
    }
}

impl TryFrom<db_access_rule::Model> for AccessRule {
    type Error = ApplicationCredentialProviderError;
    fn try_from(value: db_access_rule::Model) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value
                .external_id
                .clone()
                .unwrap_or(value.id.clone().to_string()),
            path: value.path.clone(),
            service: value.service.clone(),
            method: value.method.clone(),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::db::entity::{access_rule, application_credential};
    use chrono::{DateTime, Utc};
    use sea_orm::TryIntoModel;

    pub fn get_application_credential_mock<S: AsRef<str>>(
        id: S,
        internal_id: Option<i32>,
    ) -> application_credential::Model {
        application_credential::Model {
            internal_id: internal_id.unwrap_or_default(),
            id: id.as_ref().into(),
            name: "fake appcred".into(),
            secret_hash: "hash".into(),
            description: Some("description".into()),
            user_id: "user_id".into(),
            project_id: Some("project_id".into()),
            expires_at: Some(DateTime::<Utc>::MIN_UTC.timestamp_micros()),
            system: None,
            unrestricted: Some(true),
        }
    }

    pub fn get_application_credential_mock_from_active(
        active: application_credential::ActiveModel,
        internal_id: i32,
    ) -> application_credential::Model {
        let mut res = active;
        res.internal_id = sea_orm::Unchanged(internal_id);
        res.system = sea_orm::Unchanged(None);
        res.secret_hash = sea_orm::Unchanged("hash".into());
        res.try_into_model().unwrap()
    }

    pub fn get_access_rule_mock<S: AsRef<str>>(
        id: S,
        internal_id: Option<i32>,
    ) -> access_rule::Model {
        access_rule::Model {
            id: internal_id.unwrap_or_default(),
            external_id: Some(id.as_ref().into()),
            path: Some("/path".into()),
            method: Some("method".into()),
            service: Some("service".into()),
            user_id: None,
        }
    }
}
