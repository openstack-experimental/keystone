// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! # Centralized mock provider definitions
//!
//! All mock provider definitions consolidated into a single file. Each mock!
//! block is in its own module to avoid name conflicts between similarly named
//! types from different modules (e.g., Domain from resource vs identity).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mockall::mock;
use secrecy::SecretString;
use std::collections::HashSet;

use crate::auth::AuthenticationResult;
use crate::auth::{ExecutionContext, ScopeInfo, SecurityContext, ValidatedSecurityContext};
use crate::keystone::ServiceState;

mod api_key {
    use super::*;

    use openstack_keystone_core_types::api_key::*;

    use crate::api_key::{ApiKeyApi, ApiKeyProviderError};

    mock! {
        pub ApiKeyProvider {}

        #[async_trait]
        impl ApiKeyApi for ApiKeyProvider {
            async fn create(
                &self,
                state: &ServiceState,
                data: ApiClientResourceCreate,
            ) -> Result<ApiClientResource, ApiKeyProviderError>;

            async fn get_by_client_id<'a>(
                &self,
                state: &ServiceState,
                domain_id: &'a str,
                client_id: &'a str,
            ) -> Result<Option<ApiClientResource>, ApiKeyProviderError>;

            async fn get_by_lookup_hash<'a>(
                &self,
                state: &ServiceState,
                domain_id: &'a str,
                lookup_hash: &'a str,
            ) -> Result<Option<ApiClientResource>, ApiKeyProviderError>;

            async fn list(
                &self,
                state: &ServiceState,
                params: &ApiClientResourceListParameters,
            ) -> Result<Vec<ApiClientResource>, ApiKeyProviderError>;

            async fn update<'a>(
                &self,
                state: &ServiceState,
                domain_id: &'a str,
                client_id: &'a str,
                data: ApiClientResourceUpdate,
            ) -> Result<ApiClientResource, ApiKeyProviderError>;

            async fn revoke<'a>(
                &self,
                state: &ServiceState,
                domain_id: &'a str,
                client_id: &'a str,
                revoked_by: &'a str,
            ) -> Result<ApiClientResource, ApiKeyProviderError>;

            async fn update_last_used<'a>(
                &self,
                state: &ServiceState,
                domain_id: &'a str,
                lookup_hash: &'a str,
                last_used_at: i64,
            ) -> Result<(), ApiKeyProviderError>;

            async fn update_secret_hash<'a>(
                &self,
                state: &ServiceState,
                domain_id: &'a str,
                lookup_hash: &'a str,
                secret_hash: String,
            ) -> Result<(), ApiKeyProviderError>;

            async fn list_all(
                &self,
                state: &ServiceState,
            ) -> Result<Vec<ApiClientResource>, ApiKeyProviderError>;

            async fn purge<'a>(
                &self,
                state: &ServiceState,
                domain_id: &'a str,
                client_id: &'a str,
            ) -> Result<(), ApiKeyProviderError>;
        }
    }
}
pub use api_key::MockApiKeyProvider;

mod application_credential {
    use super::*;

    use openstack_keystone_core_types::application_credential::*;

    use crate::application_credential::{
        ApplicationCredentialApi, ApplicationCredentialProviderError,
    };

    mock! {
        pub ApplicationCredentialProvider {}

        #[async_trait]
        impl ApplicationCredentialApi for ApplicationCredentialProvider {
            async fn create_access_rule<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                rule: AccessRuleCreate,
            ) -> Result<AccessRule, ApplicationCredentialProviderError>;

            async fn create_application_credential<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                rec: ApplicationCredentialCreate,
            ) -> Result<ApplicationCredentialCreateResponse, ApplicationCredentialProviderError>;

            async fn delete_access_rule<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
                id: &'a str,
            ) -> Result<(), ApplicationCredentialProviderError>;

            async fn get_access_rule<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
                id: &'a str,
            ) -> Result<Option<AccessRule>, ApplicationCredentialProviderError>;

            async fn get_application_credential<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<Option<ApplicationCredential>, ApplicationCredentialProviderError>;

            async fn list_access_rules<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
            ) -> Result<Vec<AccessRule>, ApplicationCredentialProviderError>;

            async fn list_application_credentials<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &ApplicationCredentialListParameters,
            ) -> Result<Vec<ApplicationCredential>, ApplicationCredentialProviderError>;
        }
    }
}
pub use application_credential::MockApplicationCredentialProvider;

mod credential {
    use super::*;

    use openstack_keystone_core_types::credential::*;

    use crate::credential::{CredentialApi, CredentialProviderError};

    mock! {
        pub CredentialProvider {}

        #[async_trait]
        impl CredentialApi for CredentialProvider {
            async fn create_credential<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                rec: CredentialCreate,
            ) -> Result<Credential, CredentialProviderError>;

            async fn get_credential<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<Option<Credential>, CredentialProviderError>;

            async fn get_credential_by_ec2_access<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                access: &'a str,
            ) -> Result<Option<Credential>, CredentialProviderError>;

            async fn list_credentials<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &CredentialListParameters,
            ) -> Result<Vec<Credential>, CredentialProviderError>;

            async fn list_credentials_for_user<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
                r#type: Option<&'a str>,
            ) -> Result<Vec<Credential>, CredentialProviderError>;

            async fn update_credential<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
                rec: CredentialUpdate,
            ) -> Result<Credential, CredentialProviderError>;

            async fn delete_credential<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<(), CredentialProviderError>;

            async fn delete_credentials_for_user<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
            ) -> Result<(), CredentialProviderError>;

            async fn delete_credentials_for_project<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                project_id: &'a str,
            ) -> Result<(), CredentialProviderError>;
        }
    }
}
pub use credential::MockCredentialProvider;

mod auth_plugin_identity {
    use super::*;

    use crate::auth_plugin_identity::{AuthPluginIdentityProviderError, DynamicPluginIdentityApi};

    mock! {
        pub DynamicPluginIdentityProvider {}

        #[async_trait]
        impl DynamicPluginIdentityApi for DynamicPluginIdentityProvider {
            async fn create_or_resolve<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                plugin_name: &'a str,
                external_id: &'a str,
                user_id: &'a str,
            ) -> Result<String, AuthPluginIdentityProviderError>;

            async fn find<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                plugin_name: &'a str,
                external_id: &'a str,
            ) -> Result<Option<String>, AuthPluginIdentityProviderError>;

            async fn purge<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                plugin_name: &'a str,
                external_id: &'a str,
            ) -> Result<(), AuthPluginIdentityProviderError>;

            async fn purge_by_user<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
            ) -> Result<(), AuthPluginIdentityProviderError>;

            async fn list_by_plugin<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                plugin_name: &'a str,
            ) -> Result<Vec<(String, String)>, AuthPluginIdentityProviderError>;
        }
    }
}
pub use auth_plugin_identity::MockDynamicPluginIdentityProvider;

mod assignment {
    use super::*;

    use openstack_keystone_core_types::assignment::*;

    use crate::assignment::{AssignmentApi, AssignmentProviderError};

    mock! {
        pub AssignmentProvider {}

        #[async_trait]
        impl AssignmentApi for AssignmentProvider {
            async fn create_grant<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: AssignmentCreate,
            ) -> Result<Assignment, AssignmentProviderError>;

            async fn list_role_assignments<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &RoleAssignmentListParameters,
            ) -> Result<Vec<Assignment>, AssignmentProviderError>;

            async fn revoke_grant<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: Assignment,
            ) -> Result<(), AssignmentProviderError>;
        }
    }
}
pub use assignment::MockAssignmentProvider;

mod catalog {
    use super::*;

    use openstack_keystone_core_types::catalog::*;

    use crate::catalog::CatalogApi;
    use crate::catalog::error::CatalogProviderError;

    mock! {
        pub CatalogProvider {}

        #[async_trait]
        impl CatalogApi for CatalogProvider {
            async fn create_endpoint<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                endpoint: EndpointCreate,
            ) -> Result<Endpoint, CatalogProviderError>;

            async fn create_region<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                region: RegionCreate,
            ) -> Result<Region, CatalogProviderError>;

            async fn create_service<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                service: ServiceCreate,
            ) -> Result<Service, CatalogProviderError>;

            async fn delete_endpoint<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<(), CatalogProviderError>;

            async fn delete_region<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<(), CatalogProviderError>;

            async fn delete_service<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<(), CatalogProviderError>;

            async fn get_catalog<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                enabled: bool,
            ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError>;

            async fn get_endpoint<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<Option<Endpoint>, CatalogProviderError>;

            async fn get_region<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<Option<Region>, CatalogProviderError>;

            async fn get_service<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<Option<Service>, CatalogProviderError>;

            async fn list_endpoints<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &EndpointListParameters,
            ) -> Result<Vec<Endpoint>, CatalogProviderError>;

            async fn list_regions<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &RegionListParameters,
            ) -> Result<Vec<Region>, CatalogProviderError>;

            async fn list_services<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &ServiceListParameters,
            ) -> Result<Vec<Service>, CatalogProviderError>;

            async fn update_endpoint<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
                endpoint: EndpointUpdate,
            ) -> Result<Endpoint, CatalogProviderError>;

            async fn update_region<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
                region: RegionUpdate,
            ) -> Result<Region, CatalogProviderError>;

            async fn update_service<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
                service: ServiceUpdate,
            ) -> Result<Service, CatalogProviderError>;
        }
    }
}
pub use catalog::MockCatalogProvider;

mod federation {
    use super::*;

    use openstack_keystone_core_types::federation::*;

    use crate::federation::{FederationApi, error::FederationProviderError};

    mock! {
        pub FederationProvider {}

        #[async_trait]
        impl FederationApi for FederationProvider {
            async fn cleanup<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
            ) -> Result<(), FederationProviderError>;

            async fn create_auth_state<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                auth_state: AuthState,
            ) -> Result<AuthState, FederationProviderError>;

            async fn create_identity_provider<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                idp: IdentityProviderCreate,
            ) -> Result<IdentityProvider, FederationProviderError>;

            async fn delete_auth_state<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<(), FederationProviderError>;

            async fn delete_identity_provider<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<(), FederationProviderError>;

            async fn get_auth_state<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<Option<AuthState>, FederationProviderError>;

            async fn get_identity_provider<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<Option<IdentityProvider>, FederationProviderError>;

            async fn list_identity_providers<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &IdentityProviderListParameters,
            ) -> Result<Vec<IdentityProvider>, FederationProviderError>;

            async fn update_identity_provider<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
                idp: IdentityProviderUpdate,
            ) -> Result<IdentityProvider, FederationProviderError>;
        }
    }
}
pub use federation::MockFederationProvider;

mod identity {
    use super::*;

    use openstack_keystone_core_types::identity::*;

    use crate::identity::{IdentityApi, error::IdentityProviderError};

    mock! {
        pub IdentityProvider {}

        #[async_trait]
        impl IdentityApi for IdentityProvider {
            async fn add_user_to_group<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
                group_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn add_user_to_group_expiring<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
                group_id: &'a str,
                idp_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn add_users_to_groups<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                memberships: Vec<(&'a str, &'a str)>,
            ) -> Result<(), IdentityProviderError>;

            async fn add_users_to_groups_expiring<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                memberships: Vec<(&'a str, &'a str)>,
                idp_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn authenticate_by_password<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                auth: &UserPasswordAuthRequest,
            ) -> Result<AuthenticationResult, IdentityProviderError>;

            async fn authenticate_by_totp<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                auth: &UserTotpAuthRequest,
            ) -> Result<AuthenticationResult, IdentityProviderError>;

            async fn create_group<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                group: GroupCreate,
            ) -> Result<Group, IdentityProviderError>;

            async fn create_service_account<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                sa: ServiceAccountCreate,
            ) -> Result<ServiceAccount, IdentityProviderError>;

            async fn create_user<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user: UserCreate,
            ) -> Result<UserResponse, IdentityProviderError>;

            async fn delete_group<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                group_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn delete_user<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn update_user<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
                user: UserUpdate,
            ) -> Result<UserResponse, IdentityProviderError>;

            async fn update_user_password<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
                original_password: SecretString,
                new_password: SecretString,
            ) -> Result<(), IdentityProviderError>;

            async fn get_group<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                group_id: &'a str,
            ) -> Result<Option<Group>, IdentityProviderError>;

            async fn get_service_account<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
            ) -> Result<Option<ServiceAccount>, IdentityProviderError>;

            async fn get_user<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
            ) -> Result<Option<UserResponse>, IdentityProviderError>;

            async fn get_user_domain_id<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
            ) -> Result<String, IdentityProviderError>;

            async fn find_user_by_name_ci<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                domain_id: &'a str,
                name: &'a str,
            ) -> Result<Option<String>, IdentityProviderError>;

            async fn find_federated_user<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                idp_id: &'a str,
                unique_id: &'a str,
            ) -> Result<Option<UserResponse>, IdentityProviderError>;

            async fn list_groups<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &GroupListParameters,
            ) -> Result<Vec<Group>, IdentityProviderError>;

            async fn list_groups_of_user<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
            ) -> Result<Vec<Group>, IdentityProviderError>;

            async fn list_users_of_group<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                group_id: &'a str,
            ) -> Result<Vec<String>, IdentityProviderError>;

            async fn find_group_by_name_ci<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                domain_id: &'a str,
                name: &'a str,
            ) -> Result<Option<String>, IdentityProviderError>;

            async fn update_group<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                group_id: &'a str,
                group: GroupUpdate,
            ) -> Result<Group, IdentityProviderError>;

            async fn list_users<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &UserListParameters,
            ) -> Result<Vec<UserResponse>, IdentityProviderError>;

            async fn remove_user_from_group<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
                group_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn remove_user_from_group_expiring<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
                group_id: &'a str,
                idp_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn remove_user_from_groups<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
                group_ids: HashSet<&'a str>,
            ) -> Result<(), IdentityProviderError>;

            async fn remove_user_from_groups_expiring<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
                group_ids: HashSet<&'a str>,
                idp_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn set_user_groups<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
                group_ids: HashSet<&'a str>,
            ) -> Result<(), IdentityProviderError>;

            async fn set_user_groups_expiring<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
                group_ids: HashSet<&'a str>,
                idp_id: &'a str,
                last_verified: Option<&'a DateTime<Utc>>,
            ) -> Result<(), IdentityProviderError>;
        }
    }
}
pub use identity::MockIdentityProvider;

mod idmapping {
    use super::*;

    use openstack_keystone_core_types::idmapping::*;

    use crate::idmapping::{IdMappingApi, IdMappingProviderError};

    mock! {
        pub IdMappingProvider {}

        #[async_trait]
        impl IdMappingApi for IdMappingProvider {
            async fn get_by_local_id<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                local_id: &'a str,
                domain_id: &'a str,
                entity_type: IdMappingEntityType,
            ) -> Result<Option<IdMapping>, IdMappingProviderError>;

            async fn get_by_public_id<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                public_id: &'a str,
            ) -> Result<Option<IdMapping>, IdMappingProviderError>;
        }
    }
}
pub use idmapping::MockIdMappingProvider;

mod k8s_auth {
    use super::*;

    use openstack_keystone_core_types::k8s_auth::*;

    use crate::k8s_auth::{K8sAuthApi, K8sAuthProviderError};

    mock! {
        pub K8sAuthProvider {}

        #[async_trait]
        impl K8sAuthApi for K8sAuthProvider {
            async fn authenticate_by_k8s_mapping<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                req: &K8sAuthRequest,
            ) -> Result<AuthenticationResult, K8sAuthProviderError>;

            async fn create_auth_instance<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                config: K8sAuthInstanceCreate,
            ) -> Result<K8sAuthInstance, K8sAuthProviderError>;

            async fn delete_auth_instance<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<(), K8sAuthProviderError>;

            async fn get_auth_instance<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<Option<K8sAuthInstance>, K8sAuthProviderError>;

            async fn list_auth_instances<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &K8sAuthInstanceListParameters,
            ) -> Result<Vec<K8sAuthInstance>, K8sAuthProviderError>;

            async fn update_auth_instance<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
                data: K8sAuthInstanceUpdate,
            ) -> Result<K8sAuthInstance, K8sAuthProviderError>;
        }
    }
}
pub use k8s_auth::MockK8sAuthProvider;

mod mapping {
    use super::*;

    use openstack_keystone_core_types::mapping::*;

    use crate::mapping::{MappingApi, error::MappingProviderError};

    mock! {
        pub MappingProvider {}

        #[async_trait]
        impl MappingApi for MappingProvider {
            async fn create_ruleset<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                ruleset: MappingRuleSetCreate,
            ) -> Result<MappingRuleSet, MappingProviderError>;

            async fn delete_ruleset<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                mapping_id: &'a str,
            ) -> Result<(), MappingProviderError>;

            async fn delete_virtual_user<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
            ) -> Result<(), MappingProviderError>;

            async fn get_ruleset<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                mapping_id: &'a str,
            ) -> Result<Option<MappingRuleSet>, MappingProviderError>;

            async fn get_ruleset_by_source<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                domain_id: &'a str,
                source: &'a IdentitySource,
            ) -> Result<Option<MappingRuleSet>, MappingProviderError>;

            async fn get_virtual_user<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
            ) -> Result<Option<VirtualUser>, MappingProviderError>;

            async fn list_rulesets<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &MappingRuleSetListParameters,
            ) -> Result<Vec<MappingRuleSet>, MappingProviderError>;

            async fn mutate_rules<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                mapping_id: &'a str,
                mutations: RuleMutations,
            ) -> Result<MappingRuleSet, MappingProviderError>;

            async fn update_ruleset<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                mapping_id: &'a str,
                data: MappingRuleSetUpdate,
            ) -> Result<MappingRuleSet, MappingProviderError>;

            async fn disable_virtual_user<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
            ) -> Result<VirtualUser, MappingProviderError>;

            async fn enable_virtual_user<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                user_id: &'a str,
            ) -> Result<VirtualUser, MappingProviderError>;

            async fn authenticate_by_mapping<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                req: &'a MappingAuthRequest,
            ) -> Result<AuthenticationResult, MappingProviderError>;
        }
    }
}
pub use mapping::MockMappingProvider;

mod resource {
    use super::*;

    use openstack_keystone_core_types::resource::*;

    use crate::resource::{ResourceApi, error::ResourceProviderError};

    mock! {
        pub ResourceProvider {}

        #[async_trait]
        impl ResourceApi for ResourceProvider {
            async fn get_domain_enabled<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                domain_id: &'a str,
            ) -> Result<bool, ResourceProviderError>;

            async fn create_domain<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                domain: DomainCreate,
            ) -> Result<Domain, ResourceProviderError>;

            async fn create_project<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                project: ProjectCreate,
            ) -> Result<Project, ResourceProviderError>;

            async fn delete_domain<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<(), ResourceProviderError>;

            async fn delete_project<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<(), ResourceProviderError>;

            async fn get_domain<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                domain_id: &'a str,
            ) -> Result<Option<Domain>, ResourceProviderError>;

            async fn find_domain_by_name<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                domain_name: &'a str,
            ) -> Result<Option<Domain>, ResourceProviderError>;

            async fn get_project<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                project_id: &'a str,
            ) -> Result<Option<Project>, ResourceProviderError>;

            async fn get_project_by_name<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                name: &'a str,
                domain_id: &'a str,
            ) -> Result<Option<Project>, ResourceProviderError>;

            async fn get_project_parents<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                project_id: &'a str,
            ) -> Result<Option<Vec<Project>>, ResourceProviderError>;

            async fn list_domains<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &DomainListParameters,
            ) -> Result<Vec<Domain>, ResourceProviderError>;

            async fn list_projects<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &ProjectListParameters,
            ) -> Result<Vec<Project>, ResourceProviderError>;
        }
    }
}
pub use resource::MockResourceProvider;

mod revoke {
    use super::*;

    use openstack_keystone_core_types::revoke::*;
    use openstack_keystone_core_types::token::FernetToken;

    use crate::revoke::{RevokeApi, RevokeProviderError};

    mock! {
        pub RevokeProvider {}

        #[async_trait]
        impl RevokeApi for RevokeProvider {
            async fn create_revocation_event<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                event: RevocationEventCreate,
            ) -> Result<RevocationEvent, RevokeProviderError>;

            async fn is_token_revoked<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                token_security_context: &ValidatedSecurityContext,
            ) -> Result<bool, RevokeProviderError>;

            async fn revoke_token<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                token: &FernetToken,
            ) -> Result<(), RevokeProviderError>;
        }
    }
}
pub use revoke::MockRevokeProvider;

mod role {
    use super::*;

    use openstack_keystone_core_types::role::*;

    use crate::role::{RoleApi, RoleProviderError};

    mock! {
        pub RoleProvider {}

        #[async_trait]
        impl RoleApi for RoleProvider {
            async fn create_role<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: RoleCreate,
            ) -> Result<Role, RoleProviderError>;

            async fn create_role_imply_rule<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                prior_role_id: &'a str,
                implied_role_id: &'a str,
            ) -> Result<RoleImply, RoleProviderError>;

            async fn check_role_imply_rule<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                prior_role_id: &'a str,
                implied_role_id: &'a str,
            ) -> Result<bool, RoleProviderError>;

            async fn delete_role<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<(), RoleProviderError>;

            async fn delete_role_imply_rule<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                prior_role_id: &'a str,
                implied_role_id: &'a str,
            ) -> Result<(), RoleProviderError>;

            async fn expand_implied_roles<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                roles: &mut Vec<RoleRef>,
            ) -> Result<(), RoleProviderError>;

            async fn get_role<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<Option<Role>, RoleProviderError>;

            async fn get_role_imply_rule<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                prior_role_id: &'a str,
                implied_role_id: &'a str,
            ) -> Result<Option<RoleImply>, RoleProviderError>;

            async fn list_role_imply_rules<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
            ) -> Result<Vec<RoleImply>, RoleProviderError>;

            async fn list_role_imply_rules_by_prior<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                prior_role_id: &'a str,
            ) -> Result<Vec<RoleImply>, RoleProviderError>;

            async fn list_roles<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &RoleListParameters,
            ) -> Result<Vec<Role>, RoleProviderError>;
        }
    }
}
pub use role::MockRoleProvider;

mod token {
    use super::*;

    use openstack_keystone_core_types::token::*;

    use crate::token::TokenApi;
    use crate::token::error::TokenProviderError;

    mock! {
        pub TokenProvider {}

        #[async_trait]
        impl TokenApi for TokenProvider {
            async fn authorize_by_token<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                credential: &SecretString,
                allow_expired: Option<bool>,
                window_seconds: Option<i64>,
            ) -> Result<ValidatedSecurityContext, TokenProviderError>;

            async fn validate_to_context<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                credential: &'a str,
                allow_expired: Option<bool>,
                window_seconds: Option<i64>,
            ) -> Result<ValidatedSecurityContext, TokenProviderError>;

            #[mockall::concretize]
            async fn issue_token_context(
                &self,
                state: &ServiceState,
                ctx: &SecurityContext,
                scope: &ScopeInfo,
            ) -> Result<ValidatedSecurityContext, TokenProviderError>;

            fn encode_token(&self, token: &FernetToken) -> Result<String, TokenProviderError>;

            async fn get_token_restriction<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
                expand_roles: bool,
            ) -> Result<Option<TokenRestriction>, TokenProviderError>;

            async fn list_token_restrictions<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &TokenRestrictionListParameters,
            ) -> Result<Vec<TokenRestriction>, TokenProviderError>;

            async fn create_token_restriction<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                restriction: TokenRestrictionCreate,
            ) -> Result<TokenRestriction, TokenProviderError>;

            async fn update_token_restriction<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
                restriction: TokenRestrictionUpdate,
            ) -> Result<TokenRestriction, TokenProviderError>;

            async fn delete_token_restriction<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<(), TokenProviderError>;
        }
    }
}
pub use token::MockTokenProvider;

mod scim_realm {
    use super::*;

    use openstack_keystone_core_types::scim::*;

    use crate::scim_realm::{ScimRealmApi, error::ScimRealmProviderError};

    mock! {
        pub ScimRealmProvider {}

        #[async_trait]
        impl ScimRealmApi for ScimRealmProvider {
            async fn create_realm<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                data: ScimRealmResourceCreate,
            ) -> Result<ScimRealmResource, ScimRealmProviderError>;

            async fn get_realm<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                domain_id: &'a str,
                provider_id: &'a str,
            ) -> Result<Option<ScimRealmResource>, ScimRealmProviderError>;

            async fn list_realms<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &ScimRealmResourceListParameters,
            ) -> Result<Vec<ScimRealmResource>, ScimRealmProviderError>;

            async fn update_realm<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                domain_id: &'a str,
                provider_id: &'a str,
                data: ScimRealmResourceUpdate,
            ) -> Result<ScimRealmResource, ScimRealmProviderError>;
        }
    }
}
pub use scim_realm::MockScimRealmProvider;

mod scim_resource {
    use super::*;

    use openstack_keystone_core_types::scim::*;

    use crate::scim_resource::{ScimResourceApi, error::ScimResourceProviderError};

    mock! {
        pub ScimResourceProvider {}

        #[async_trait]
        impl ScimResourceApi for ScimResourceProvider {
            async fn create_index<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                data: ScimResourceIndexCreate,
            ) -> Result<ScimResourceIndex, ScimResourceProviderError>;

            async fn get_index<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                domain_id: &'a str,
                provider_id: &'a str,
                resource_type: ScimResourceType,
                keystone_id: &'a str,
            ) -> Result<Option<ScimResourceIndex>, ScimResourceProviderError>;

            async fn get_index_by_external_id<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                domain_id: &'a str,
                provider_id: &'a str,
                resource_type: ScimResourceType,
                external_id: &'a str,
            ) -> Result<Option<ScimResourceIndex>, ScimResourceProviderError>;

            async fn list_index<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                domain_id: &'a str,
                provider_id: &'a str,
                resource_type: ScimResourceType,
            ) -> Result<Vec<ScimResourceIndex>, ScimResourceProviderError>;

            async fn update_index<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                domain_id: &'a str,
                provider_id: &'a str,
                resource_type: ScimResourceType,
                keystone_id: &'a str,
                data: ScimResourceIndexUpdate,
                expected_version: Option<u64>,
            ) -> Result<ScimResourceIndex, ScimResourceProviderError>;

            async fn list_all_index<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
            ) -> Result<Vec<ScimResourceIndex>, ScimResourceProviderError>;

            async fn purge_index<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                domain_id: &'a str,
                provider_id: &'a str,
                resource_type: ScimResourceType,
                keystone_id: &'a str,
            ) -> Result<(), ScimResourceProviderError>;
        }
    }
}
pub use scim_resource::MockScimResourceProvider;

mod trust {
    use super::*;

    use openstack_keystone_core_types::trust::*;

    use crate::trust::{TrustApi, TrustProviderError};

    mock! {
        pub TrustProvider {}

        #[async_trait]
        impl TrustApi for TrustProvider {
            async fn get_trust<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<Option<Trust>, TrustProviderError>;

            async fn get_trust_delegation_chain<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                id: &'a str,
            ) -> Result<Option<Vec<Trust>>, TrustProviderError>;

            async fn list_trusts<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                params: &TrustListParameters,
            ) -> Result<Vec<Trust>, TrustProviderError>;

            async fn validate_trust_delegation_chain<'a>(
                &self,
                ctx: &ExecutionContext<'a>,
                trust: &Trust,
            ) -> Result<bool, TrustProviderError>;
        }
    }
}
pub use trust::MockTrustProvider;
