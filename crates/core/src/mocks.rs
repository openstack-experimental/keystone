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
use crate::auth::{ScopeInfo, SecurityContext, ValidatedSecurityContext};
use crate::keystone::ServiceState;

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
            async fn create_access_rule(
                &self,
                state: &ServiceState,
                rule: AccessRuleCreate,
            ) -> Result<AccessRule, ApplicationCredentialProviderError>;

            async fn create_application_credential(
                &self,
                state: &ServiceState,
                rec: ApplicationCredentialCreate,
            ) -> Result<ApplicationCredentialCreateResponse, ApplicationCredentialProviderError>;

            async fn delete_access_rule<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
                id: &'a str,
            ) -> Result<(), ApplicationCredentialProviderError>;

            async fn get_access_rule<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
                id: &'a str,
            ) -> Result<Option<AccessRule>, ApplicationCredentialProviderError>;

            async fn get_application_credential<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<Option<ApplicationCredential>, ApplicationCredentialProviderError>;

            async fn list_access_rules<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
            ) -> Result<Vec<AccessRule>, ApplicationCredentialProviderError>;

            async fn list_application_credentials(
                &self,
                state: &ServiceState,
                params: &ApplicationCredentialListParameters,
            ) -> Result<Vec<ApplicationCredential>, ApplicationCredentialProviderError>;
        }
    }
}
pub use application_credential::MockApplicationCredentialProvider;

mod assignment {
    use super::*;

    use openstack_keystone_core_types::assignment::*;

    use crate::assignment::{AssignmentApi, AssignmentProviderError};

    mock! {
        pub AssignmentProvider {}

        #[async_trait]
        impl AssignmentApi for AssignmentProvider {
            async fn create_grant(
                &self,
                state: &ServiceState,
                params: AssignmentCreate,
            ) -> Result<Assignment, AssignmentProviderError>;

            async fn list_role_assignments(
                &self,
                state: &ServiceState,
                params: &RoleAssignmentListParameters,
            ) -> Result<Vec<Assignment>, AssignmentProviderError>;

            async fn revoke_grant(
                &self,
                state: &ServiceState,
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
            async fn create_endpoint(
                &self,
                state: &ServiceState,
                endpoint: EndpointCreate,
            ) -> Result<Endpoint, CatalogProviderError>;

            async fn create_region(
                &self,
                state: &ServiceState,
                region: RegionCreate,
            ) -> Result<Region, CatalogProviderError>;

            async fn create_service(
                &self,
                state: &ServiceState,
                service: ServiceCreate,
            ) -> Result<Service, CatalogProviderError>;

            async fn delete_endpoint<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<(), CatalogProviderError>;

            async fn delete_region<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<(), CatalogProviderError>;

            async fn delete_service<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<(), CatalogProviderError>;

            async fn get_catalog(
                &self,
                state: &ServiceState,
                enabled: bool,
            ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError>;

            async fn get_endpoint<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<Option<Endpoint>, CatalogProviderError>;

            async fn get_region<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<Option<Region>, CatalogProviderError>;

            async fn get_service<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<Option<Service>, CatalogProviderError>;

            async fn list_endpoints(
                &self,
                state: &ServiceState,
                params: &EndpointListParameters,
            ) -> Result<Vec<Endpoint>, CatalogProviderError>;

            async fn list_regions(
                &self,
                state: &ServiceState,
                params: &RegionListParameters,
            ) -> Result<Vec<Region>, CatalogProviderError>;

            async fn list_services(
                &self,
                state: &ServiceState,
                params: &ServiceListParameters,
            ) -> Result<Vec<Service>, CatalogProviderError>;

            async fn update_endpoint<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
                endpoint: EndpointUpdate,
            ) -> Result<Endpoint, CatalogProviderError>;

            async fn update_region<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
                region: RegionUpdate,
            ) -> Result<Region, CatalogProviderError>;

            async fn update_service<'a>(
                &self,
                state: &ServiceState,
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
            async fn cleanup(
                &self,
                state: &ServiceState,
            ) -> Result<(), FederationProviderError>;

            async fn create_auth_state(
                &self,
                state: &ServiceState,
                auth_state: AuthState,
            ) -> Result<AuthState, FederationProviderError>;

            async fn create_identity_provider(
                &self,
                state: &ServiceState,
                idp: IdentityProviderCreate,
            ) -> Result<IdentityProvider, FederationProviderError>;

            async fn delete_auth_state<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<(), FederationProviderError>;

            async fn delete_identity_provider<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<(), FederationProviderError>;

            async fn get_auth_state<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<Option<AuthState>, FederationProviderError>;

            async fn get_identity_provider<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<Option<IdentityProvider>, FederationProviderError>;

            async fn list_identity_providers(
                &self,
                state: &ServiceState,
                params: &IdentityProviderListParameters,
            ) -> Result<Vec<IdentityProvider>, FederationProviderError>;

            async fn update_identity_provider<'a>(
                &self,
                state: &ServiceState,
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
                state: &ServiceState,
                user_id: &'a str,
                group_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn add_user_to_group_expiring<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
                group_id: &'a str,
                idp_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn add_users_to_groups<'a>(
                &self,
                state: &ServiceState,
                memberships: Vec<(&'a str, &'a str)>,
            ) -> Result<(), IdentityProviderError>;

            async fn add_users_to_groups_expiring<'a>(
                &self,
                state: &ServiceState,
                memberships: Vec<(&'a str, &'a str)>,
                idp_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn authenticate_by_password(
                &self,
                state: &ServiceState,
                auth: &UserPasswordAuthRequest,
            ) -> Result<AuthenticationResult, IdentityProviderError>;

            async fn create_group(
                &self,
                state: &ServiceState,
                group: GroupCreate,
            ) -> Result<Group, IdentityProviderError>;

            async fn create_service_account(
                &self,
                state: &ServiceState,
                sa: ServiceAccountCreate,
            ) -> Result<ServiceAccount, IdentityProviderError>;

            async fn create_user(
                &self,
                state: &ServiceState,
                user: UserCreate,
            ) -> Result<UserResponse, IdentityProviderError>;

            async fn delete_group<'a>(
                &self,
                state: &ServiceState,
                group_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn delete_user<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn update_user<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
                user: UserUpdate,
            ) -> Result<UserResponse, IdentityProviderError>;

            async fn update_user_password<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
                original_password: SecretString,
                new_password: SecretString,
            ) -> Result<(), IdentityProviderError>;

            async fn get_group<'a>(
                &self,
                state: &ServiceState,
                group_id: &'a str,
            ) -> Result<Option<Group>, IdentityProviderError>;

            async fn get_service_account<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
            ) -> Result<Option<ServiceAccount>, IdentityProviderError>;

            async fn get_user<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
            ) -> Result<Option<UserResponse>, IdentityProviderError>;

            async fn get_user_domain_id<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
            ) -> Result<String, IdentityProviderError>;

            async fn find_federated_user<'a>(
                &self,
                state: &ServiceState,
                idp_id: &'a str,
                unique_id: &'a str,
            ) -> Result<Option<UserResponse>, IdentityProviderError>;

            async fn list_groups(
                &self,
                state: &ServiceState,
                params: &GroupListParameters,
            ) -> Result<Vec<Group>, IdentityProviderError>;

            async fn list_groups_of_user<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
            ) -> Result<Vec<Group>, IdentityProviderError>;

            async fn list_users(
                &self,
                state: &ServiceState,
                params: &UserListParameters,
            ) -> Result<Vec<UserResponse>, IdentityProviderError>;

            async fn remove_user_from_group<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
                group_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn remove_user_from_group_expiring<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
                group_id: &'a str,
                idp_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn remove_user_from_groups<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
                group_ids: HashSet<&'a str>,
            ) -> Result<(), IdentityProviderError>;

            async fn remove_user_from_groups_expiring<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
                group_ids: HashSet<&'a str>,
                idp_id: &'a str,
            ) -> Result<(), IdentityProviderError>;

            async fn set_user_groups<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
                group_ids: HashSet<&'a str>,
            ) -> Result<(), IdentityProviderError>;

            async fn set_user_groups_expiring<'a>(
                &self,
                state: &ServiceState,
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
                state: &ServiceState,
                local_id: &'a str,
                domain_id: &'a str,
                entity_type: IdMappingEntityType,
            ) -> Result<Option<IdMapping>, IdMappingProviderError>;

            async fn get_by_public_id<'a>(
                &self,
                state: &ServiceState,
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
            async fn authenticate_by_k8s_mapping(
                &self,
                state: &ServiceState,
                req: &K8sAuthRequest,
            ) -> Result<AuthenticationResult, K8sAuthProviderError>;

            async fn create_auth_instance(
                &self,
                state: &ServiceState,
                config: K8sAuthInstanceCreate,
            ) -> Result<K8sAuthInstance, K8sAuthProviderError>;

            async fn delete_auth_instance<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<(), K8sAuthProviderError>;

            async fn get_auth_instance<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<Option<K8sAuthInstance>, K8sAuthProviderError>;

            async fn list_auth_instances(
                &self,
                state: &ServiceState,
                params: &K8sAuthInstanceListParameters,
            ) -> Result<Vec<K8sAuthInstance>, K8sAuthProviderError>;

            async fn update_auth_instance<'a>(
                &self,
                state: &ServiceState,
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
            async fn create_ruleset(
                &self,
                state: &ServiceState,
                ruleset: MappingRuleSetCreate,
            ) -> Result<MappingRuleSet, MappingProviderError>;

            async fn delete_ruleset<'a>(
                &self,
                state: &ServiceState,
                mapping_id: &'a str,
            ) -> Result<(), MappingProviderError>;

            async fn delete_virtual_user<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
            ) -> Result<(), MappingProviderError>;

            async fn get_ruleset<'a>(
                &self,
                state: &ServiceState,
                mapping_id: &'a str,
            ) -> Result<Option<MappingRuleSet>, MappingProviderError>;

            async fn get_ruleset_by_source<'a>(
                &self,
                state: &ServiceState,
                domain_id: &'a str,
                source: &'a IdentitySource,
            ) -> Result<Option<MappingRuleSet>, MappingProviderError>;

            async fn get_virtual_user<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
            ) -> Result<Option<VirtualUser>, MappingProviderError>;

            async fn list_rulesets(
                &self,
                state: &ServiceState,
                params: &MappingRuleSetListParameters,
            ) -> Result<Vec<MappingRuleSet>, MappingProviderError>;

            async fn mutate_rules<'a>(
                &self,
                state: &ServiceState,
                mapping_id: &'a str,
                mutations: RuleMutations,
            ) -> Result<MappingRuleSet, MappingProviderError>;

            async fn update_ruleset<'a>(
                &self,
                state: &ServiceState,
                mapping_id: &'a str,
                data: MappingRuleSetUpdate,
            ) -> Result<MappingRuleSet, MappingProviderError>;

            async fn disable_virtual_user<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
            ) -> Result<VirtualUser, MappingProviderError>;

            async fn enable_virtual_user<'a>(
                &self,
                state: &ServiceState,
                user_id: &'a str,
            ) -> Result<VirtualUser, MappingProviderError>;

            async fn authenticate_by_mapping(
                &self,
                state: &ServiceState,
                req: &MappingAuthRequest,
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
                state: &ServiceState,
                domain_id: &'a str,
            ) -> Result<bool, ResourceProviderError>;

            async fn create_domain(
                &self,
                state: &ServiceState,
                domain: DomainCreate,
            ) -> Result<Domain, ResourceProviderError>;

            async fn create_project(
                &self,
                state: &ServiceState,
                project: ProjectCreate,
            ) -> Result<Project, ResourceProviderError>;

            async fn delete_domain<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<(), ResourceProviderError>;

            async fn delete_project<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<(), ResourceProviderError>;

            async fn get_domain<'a>(
                &self,
                state: &ServiceState,
                domain_id: &'a str,
            ) -> Result<Option<Domain>, ResourceProviderError>;

            async fn find_domain_by_name<'a>(
                &self,
                state: &ServiceState,
                domain_name: &'a str,
            ) -> Result<Option<Domain>, ResourceProviderError>;

            async fn get_project<'a>(
                &self,
                state: &ServiceState,
                project_id: &'a str,
            ) -> Result<Option<Project>, ResourceProviderError>;

            async fn get_project_by_name<'a>(
                &self,
                state: &ServiceState,
                name: &'a str,
                domain_id: &'a str,
            ) -> Result<Option<Project>, ResourceProviderError>;

            async fn get_project_parents<'a>(
                &self,
                state: &ServiceState,
                project_id: &'a str,
            ) -> Result<Option<Vec<Project>>, ResourceProviderError>;

            async fn list_domains(
                &self,
                state: &ServiceState,
                params: &DomainListParameters,
            ) -> Result<Vec<Domain>, ResourceProviderError>;

            async fn list_projects(
                &self,
                state: &ServiceState,
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
            async fn create_revocation_event(
                &self,
                state: &ServiceState,
                event: RevocationEventCreate,
            ) -> Result<RevocationEvent, RevokeProviderError>;

            async fn is_token_revoked(
                &self,
                state: &ServiceState,
                token_security_context: &ValidatedSecurityContext,
            ) -> Result<bool, RevokeProviderError>;

            async fn revoke_token(
                &self,
                state: &ServiceState,
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
            async fn create_role(
                &self,
                state: &ServiceState,
                params: RoleCreate,
            ) -> Result<Role, RoleProviderError>;

            async fn create_role_imply_rule<'a>(
                &self,
                state: &ServiceState,
                prior_role_id: &'a str,
                implied_role_id: &'a str,
            ) -> Result<RoleImply, RoleProviderError>;

            async fn check_role_imply_rule<'a>(
                &self,
                state: &ServiceState,
                prior_role_id: &'a str,
                implied_role_id: &'a str,
            ) -> Result<bool, RoleProviderError>;

            async fn delete_role<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<(), RoleProviderError>;

            async fn delete_role_imply_rule<'a>(
                &self,
                state: &ServiceState,
                prior_role_id: &'a str,
                implied_role_id: &'a str,
            ) -> Result<(), RoleProviderError>;

            async fn expand_implied_roles(
                &self,
                state: &ServiceState,
                roles: &mut Vec<RoleRef>,
            ) -> Result<(), RoleProviderError>;

            async fn get_role<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<Option<Role>, RoleProviderError>;

            async fn get_role_imply_rule<'a>(
                &self,
                state: &ServiceState,
                prior_role_id: &'a str,
                implied_role_id: &'a str,
            ) -> Result<Option<RoleImply>, RoleProviderError>;

            async fn list_role_imply_rules(
                &self,
                state: &ServiceState,
            ) -> Result<Vec<RoleImply>, RoleProviderError>;

            async fn list_role_imply_rules_by_prior<'a>(
                &self,
                state: &ServiceState,
                prior_role_id: &'a str,
            ) -> Result<Vec<RoleImply>, RoleProviderError>;

            async fn list_roles(
                &self,
                state: &ServiceState,
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
                state: &ServiceState,
                credential: &'a str,
                allow_expired: Option<bool>,
                window_seconds: Option<i64>,
            ) -> Result<ValidatedSecurityContext, TokenProviderError>;

            async fn validate_to_context<'a>(
                &self,
                state: &ServiceState,
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
                state: &ServiceState,
                id: &'a str,
                expand_roles: bool,
            ) -> Result<Option<TokenRestriction>, TokenProviderError>;

            async fn list_token_restrictions<'a>(
                &self,
                state: &ServiceState,
                params: &TokenRestrictionListParameters,
            ) -> Result<Vec<TokenRestriction>, TokenProviderError>;

            async fn create_token_restriction<'a>(
                &self,
                state: &ServiceState,
                restriction: TokenRestrictionCreate,
            ) -> Result<TokenRestriction, TokenProviderError>;

            async fn update_token_restriction<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
                restriction: TokenRestrictionUpdate,
            ) -> Result<TokenRestriction, TokenProviderError>;

            async fn delete_token_restriction<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<(), TokenProviderError>;
        }
    }
}
pub use token::MockTokenProvider;

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
                state: &ServiceState,
                id: &'a str,
            ) -> Result<Option<Trust>, TrustProviderError>;

            async fn get_trust_delegation_chain<'a>(
                &self,
                state: &ServiceState,
                id: &'a str,
            ) -> Result<Option<Vec<Trust>>, TrustProviderError>;

            async fn list_trusts(
                &self,
                state: &ServiceState,
                params: &TrustListParameters,
            ) -> Result<Vec<Trust>, TrustProviderError>;

            async fn validate_trust_delegation_chain(
                &self,
                state: &ServiceState,
                trust: &Trust,
            ) -> Result<bool, TrustProviderError>;
        }
    }
}
pub use trust::MockTrustProvider;
