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
//! # Catalog API types
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::{Validate, ValidationErrors};

use crate::error::BuilderError;

/// A catalog object.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Catalog(pub Vec<CatalogService>);

impl Validate for Catalog {
    fn validate(&self) -> Result<(), ValidationErrors> {
        self.0.validate()
    }
}

impl IntoResponse for Catalog {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// A catalog object.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct CatalogService {
    pub r#type: Option<String>,
    #[validate(length(max = 255))]
    pub name: Option<String>,
    #[validate(length(max = 64))]
    pub id: String,
    #[validate(nested)]
    pub endpoints: Vec<Endpoint>,
}

/// A Catalog Endpoint.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Endpoint {
    #[validate(length(max = 64))]
    pub id: String,
    #[validate(url)]
    pub url: String,
    #[validate(length(max = 64))]
    pub interface: String,
    #[builder(default)]
    #[validate(length(max = 64))]
    pub region: Option<String>,
    #[builder(default)]
    #[validate(length(max = 64))]
    pub region_id: Option<String>,
}
