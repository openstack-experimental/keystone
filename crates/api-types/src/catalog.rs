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
use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

/// A catalog object.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Catalog(pub Vec<CatalogService>);

#[cfg(feature = "validate")]
impl validator::Validate for Catalog {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        self.0.validate()
    }
}

/// A catalog object.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct CatalogService {
    pub r#type: Option<String>,
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,
    #[cfg_attr(feature = "validate", validate(nested))]
    pub endpoints: Vec<Endpoint>,
}

/// A Catalog Endpoint.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Endpoint {
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,
    #[cfg_attr(feature = "validate", validate(url))]
    pub url: String,
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub interface: String,
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub region: Option<String>,
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub region_id: Option<String>,
}
