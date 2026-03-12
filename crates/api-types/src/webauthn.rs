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
//! # WebauthN extension api types

pub mod allow_credentials;
pub mod attestation_conveyance_preference;
pub mod attestation_format;
pub mod auth;
pub mod authentication_extensions_client_outputs;
pub mod authenticator_assertion_response_raw;
pub mod authenticator_attachment;
pub mod authenticator_selection_criteria;
pub mod authenticator_transport;
pub mod cred_protect;
pub mod credential_protection_policy;
pub mod error;
pub mod hmac_get_secret_input;
pub mod hmac_get_secret_output;
pub mod pub_key_cred_params;
pub mod public_key_credential_creation_options;
pub mod public_key_credential_descriptor;
pub mod public_key_credential_hints;
pub mod public_key_credential_request_options;
pub mod register;
pub mod relying_party;
pub mod request_authentication_extensions;
pub mod request_registration_extension;
pub mod resident_key_requirement;
pub mod user;
pub mod user_verification_policy;

pub use allow_credentials::*;
pub use attestation_conveyance_preference::*;
pub use attestation_format::*;
pub use auth::*;
pub use authentication_extensions_client_outputs::*;
pub use authenticator_assertion_response_raw::*;
pub use authenticator_attachment::*;
pub use authenticator_selection_criteria::*;
pub use authenticator_transport::*;
pub use cred_protect::*;
pub use credential_protection_policy::*;
pub use error::*;
pub use hmac_get_secret_input::*;
pub use hmac_get_secret_output::*;
pub use pub_key_cred_params::*;
pub use public_key_credential_creation_options::*;
pub use public_key_credential_descriptor::*;
pub use public_key_credential_hints::*;
pub use public_key_credential_request_options::*;
pub use register::*;
pub use relying_party::*;
pub use request_authentication_extensions::*;
pub use request_registration_extension::*;
pub use resident_key_requirement::*;
pub use user::*;
pub use user_verification_policy::*;
