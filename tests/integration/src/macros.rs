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

#[macro_export]
macro_rules! impl_deleter {
    ($state:ty, $resource:ty, $provider_getter:ident, $method:ident) => {
        impl ResourceDeleter<$resource> for Arc<$state> {
            fn delete(&self, resource: $resource) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async move {
                    self.provider
                        .$provider_getter()
                        .$method(self, &resource.id)
                        .await;
                })
            }
        }
    };
}

#[macro_export]
macro_rules! create_domain {
    ($state:ident) => {
        crate::resource::create_domain(
            &$state,
            openstack_keystone_core_types::resource::DomainCreateBuilder::default()
                .name(uuid::Uuid::new_v4().simple().to_string())
                .build()?,
        )
        .await
    };
}

#[macro_export]
macro_rules! create_project {
    ($state:ident, $domain_id:expr) => {
        crate::resource::create_project(
            &$state,
            openstack_keystone_core_types::resource::ProjectCreateBuilder::default()
                .name(uuid::Uuid::new_v4().simple().to_string())
                .domain_id($domain_id)
                .parent_id($domain_id)
                .build()?,
        )
        .await
    };
    ($state:ident, $domain_id:expr, $parent_id:expr) => {
        crate::resource::create_project(
            &$state,
            openstack_keystone_core_types::resource::ProjectCreateBuilder::default()
                .name(uuid::Uuid::new_v4().simple().to_string())
                .domain_id($domain_id)
                .parent_id($parent_id)
                .build()?,
        )
        .await
    };
}

#[macro_export]
macro_rules! create_role {
    ($state:ident) => {
        crate::role::create_role(
            &$state,
            openstack_keystone_core_types::role::RoleCreateBuilder::default()
                .name(uuid::Uuid::new_v4().simple().to_string())
                .build()?,
        )
        .await
    };
    ($state:ident, $name:expr) => {
        crate::role::create_role(
            &$state,
            openstack_keystone_core_types::role::RoleCreateBuilder::default()
                .name($name)
                .build()?,
        )
        .await
    };
    ($state:ident, $name:expr, $domain_id:expr) => {
        crate::role::create_role(
            &$state,
            openstack_keystone_core_types::role::RoleCreateBuilder::default()
                .name($name)
                .domain_id($domain_id)
                .build()?,
        )
        .await
    };
}

#[macro_export]
macro_rules! create_user {
    ($state:ident, $domain_id:expr) => {
        crate::identity::create_user(
            &$state,
            openstack_keystone_core_types::identity::UserCreateBuilder::default()
                .name(uuid::Uuid::new_v4().simple().to_string())
                .domain_id($domain_id)
                .build()?,
        )
        .await
    };
}

#[macro_export]
macro_rules! create_group {
    ($state:ident, $domain_id:expr) => {
        crate::identity::create_group(
            &$state,
            openstack_keystone_core_types::identity::GroupCreateBuilder::default()
                .name(uuid::Uuid::new_v4().simple().to_string())
                .domain_id($domain_id)
                .build()?,
        )
        .await
    };
}

#[macro_export]
macro_rules! create_application_credential {
    ($state:ident, $user_id:expr, $project_id:expr) => {
        crate::application_credential::create_application_credential(
            &$state,
            openstack_keystone_core_types::application_credential::ApplicationCredentialCreateBuilder::default()
                .name(uuid::Uuid::new_v4().simple().to_string())
                .user_id($user_id)
                .project_id($project_id)
                .roles(Vec::new())
                .build()?,
        )
        .await
    };
}
