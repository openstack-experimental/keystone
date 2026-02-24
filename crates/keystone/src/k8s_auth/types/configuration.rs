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
//! # K8s Auth configuration types.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::error::BuilderError;

/// K8s authentication configuration.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthConfiguration {
    /// PEM encoded CA cert for use by the TLS client used to talk with the
    /// Kubernetes API. NOTE: Every line must end with a newline: \n If not set,
    /// the local CA cert will be used if running in a Kubernetes pod.
    #[builder(default)]
    pub ca_cert: Option<String>,

    /// Disable defaulting to the local CA cert and service account JWT when
    /// running in a Kubernetes pod.
    #[builder(default)]
    pub disable_local_ca_jwt: bool,

    /// Domain ID owning the K8s auth configuration.
    pub domain_id: String,

    pub enabled: bool,

    /// Host must be a host string, a host:port pair, or a URL to the base of
    /// the Kubernetes API server.
    pub host: String,

    /// K8s auth configuration ID.
    pub id: String,

    /// K8s auth name.
    #[builder(default)]
    pub name: Option<String>,
}

/// New K8s authentication configuration.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthConfigurationCreate {
    /// PEM encoded CA cert for use by the TLS client used to talk with the
    /// Kubernetes API. NOTE: Every line must end with a newline: \n If not set,
    /// the local CA cert will be used if running in a Kubernetes pod.
    pub ca_cert: Option<String>,

    /// Disable defaulting to the local CA cert and service account JWT when
    /// running in a Kubernetes pod.
    #[builder(default)]
    pub disable_local_ca_jwt: Option<bool>,

    /// Domain ID owning the K8s auth configuration.
    pub domain_id: String,

    pub enabled: bool,

    /// Host must be a host string, a host:port pair, or a URL to the base of
    /// the Kubernetes API server.
    pub host: String,

    /// Optional ID for the configuration
    pub id: Option<String>,

    /// K8s auth name.
    #[builder(default)]
    pub name: Option<String>,
}

/// Update K8s authentication configuration.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthConfigurationUpdate {
    /// PEM encoded CA cert for use by the TLS client used to talk with the
    /// Kubernetes API. NOTE: Every line must end with a newline: \n If not set,
    /// the local CA cert will be used if running in a Kubernetes pod.
    #[builder(default)]
    pub ca_cert: Option<String>,

    /// Disable defaulting to the local CA cert and service account JWT when
    /// running in a Kubernetes pod.
    #[builder(default)]
    pub disable_local_ca_jwt: Option<bool>,

    #[builder(default)]
    pub enabled: Option<bool>,

    /// Host must be a host string, a host:port pair, or a URL to the base of
    /// the Kubernetes API server.
    #[builder(default)]
    pub host: Option<String>,

    /// K8s auth name.
    #[builder(default)]
    pub name: Option<String>,
}

/// K8s Auth configuration list parameters.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(build_fn(error = "BuilderError"))]
pub struct K8sAuthConfigurationListParameters {
    /// Domain id.
    pub domain_id: Option<String>,
    /// Name.
    pub name: Option<String>,
}
