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
//! OS-EC2 credential helpers (`/v3/users/{user_id}/credentials/OS-EC2`),
//! generated with [`crate::macros::crud_endpoint`].
//!
//! This legacy API is a user sub-resource whose create body is not wrapped
//! in a resource key, so the blocks below set `parent` and omit `body_key`.
//! The authorization tests create a credential with one session and delete
//! it with another, so the unguarded flavors are used rather than the
//! [`crate::guard`]-based ones.

use std::sync::Arc;

use eyre::Result;

use openstack_keystone_api_types::v3::os_ec2_credential::*;
use openstack_sdk::AsyncOpenStack;

use crate::macros::crud_endpoint;

crud_endpoint! {
    create_unguarded {
        request = Ec2CredentialCreateApiRequest,
        func = create_ec2_credential_with_body,
        parent = ("users", user_id),
        path = "credentials/OS-EC2",
        create_type = Ec2CredentialCreateRequest,
        model = Ec2Credential,
        response_key = "credential",
        service = Identity,
        api_version = (3, 0),
    }
    show {
        request = Ec2CredentialShowApiRequest,
        func = get_ec2_credential,
        parent = ("users", user_id),
        path = "credentials/OS-EC2",
        model = Ec2Credential,
        response_key = "credential",
        service = Identity,
        api_version = (3, 0),
    }
    list {
        request = Ec2CredentialListRequest,
        func = list_ec2_credentials,
        parent = ("users", user_id),
        path = "credentials/OS-EC2",
        model = Ec2Credential,
        response_key = "credentials",
        service = Identity,
        api_version = (3, 0),
        query = [],
    }
    delete_fn {
        request = Ec2CredentialDeleteApiRequest,
        func = delete_ec2_credential,
        parent = ("users", user_id),
        path = "credentials/OS-EC2",
        service = Identity,
        api_version = (3, 0),
    }
}

/// Create an EC2 credential for `user_id` bound to `project_id`, letting the
/// server generate the access/secret pair (ADR 0019 §2, "Automatic
/// Creation").
pub async fn create_ec2_credential(
    tc: &Arc<AsyncOpenStack>,
    user_id: &str,
    project_id: &str,
) -> Result<Ec2Credential> {
    create_ec2_credential_with_body(
        tc,
        user_id,
        Ec2CredentialCreateRequest {
            project_id: project_id.to_string(),
            access: None,
            secret: None,
        },
    )
    .await
}
