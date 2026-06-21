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
//! Mock implementations for OpenStack Keystone core provider APIs.
//!
//! This crate provides mockall-generated mock types for all 13 provider
//! API traits used by `openstack-keystone-core`. Each mock type can be
//! used in tests to stub out provider interactions.
//!
//! # Usage
//!
//! ```rust,ignore
//! use openstack_keystone_core_mock::{
//!     MockRoleAssignmentProvider, MockMappingProvider, mocked_builder,
//! };
//!
//! let provider_builder = mocked_builder();
//! ```

use async_trait::async_trait;
use mockall::mock;

use crate::application_credential::{ApplicationCredentialApi, ApplicationCredentialProviderError};
use crate::assignment::{AssignmentApi, AssignmentProviderError};
use crate::auth::AuthenticationResult;
use crate::auth::ScopeInfo as CoreScopeInfo;
use crate::auth::SecurityContext;
use crate::auth::ValidatedSecurityContext;
use crate::catalog::{CatalogApi, CatalogProviderError};
use crate::federation::{FederationApi, error::FederationProviderError};
use crate::identity::{IdentityApi, IdentityProviderError};
use crate::idmapping::{IdMappingApi, IdMappingProviderError};
use crate::k8s_auth::{K8sAuthApi, K8sAuthProviderError};
use crate::keystone::ServiceState;
use crate::mapping::{MappingApi, error::MappingProviderError};
use crate::resource::{ResourceApi, ResourceProviderError};
use crate::revoke::{RevokeApi, RevokeProviderError};
use crate::role::{RoleApi, RoleProviderError};
use crate::token::{TokenApi, TokenProviderError};
use crate::trust::{TrustApi, TrustProviderError};
use openstack_keystone_core_types::token::FernetToken;

// ==================== AssignmentApi Mock ====================

mock! {
    pub AssignmentProvider {}

    #[async_trait]
    impl AssignmentApi for AssignmentProvider {
        async fn create_grant(
            &self,
            state: &ServiceState,
            params: openstack_keystone_core_types::assignment::AssignmentCreate,
        ) -> Result<openstack_keystone_core_types::assignment::Assignment, AssignmentProviderError>;

        async fn list_role_assignments(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::assignment::RoleAssignmentListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::assignment::Assignment>, AssignmentProviderError>;

        async fn revoke_grant(
            &self,
            state: &ServiceState,
            params: openstack_keystone_core_types::assignment::Assignment,
        ) -> Result<(), AssignmentProviderError>;
    }
}

// ==================== MappingApi Mock ====================

mock! {
    pub MappingProvider {}

    #[async_trait]
    impl MappingApi for MappingProvider {
        async fn create_ruleset(
            &self,
            state: &ServiceState,
            ruleset: openstack_keystone_core_types::mapping::ruleset::MappingRuleSetCreate,
        ) -> Result<openstack_keystone_core_types::mapping::ruleset::MappingRuleSet, MappingProviderError>;

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
        ) -> Result<Option<openstack_keystone_core_types::mapping::ruleset::MappingRuleSet>, MappingProviderError>;

        async fn get_ruleset_by_source<'a>(
            &self,
            state: &ServiceState,
            domain_id: &'a str,
            source: &'a openstack_keystone_core_types::mapping::resolution::IdentitySource,
        ) -> Result<Option<openstack_keystone_core_types::mapping::ruleset::MappingRuleSet>, MappingProviderError>;

        async fn get_virtual_user<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::mapping::VirtualUser>, MappingProviderError>;

        async fn list_rulesets(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::mapping::ruleset::MappingRuleSetListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::mapping::ruleset::MappingRuleSet>, MappingProviderError>;

        async fn mutate_rules<'a>(
            &self,
            state: &ServiceState,
            mapping_id: &'a str,
            mutations: openstack_keystone_core_types::mapping::RuleMutations,
        ) -> Result<openstack_keystone_core_types::mapping::ruleset::MappingRuleSet, MappingProviderError>;

        async fn update_ruleset<'a>(
            &self,
            state: &ServiceState,
            mapping_id: &'a str,
            data: openstack_keystone_core_types::mapping::ruleset::MappingRuleSetUpdate,
        ) -> Result<openstack_keystone_core_types::mapping::ruleset::MappingRuleSet, MappingProviderError>;

        async fn disable_virtual_user<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<openstack_keystone_core_types::mapping::VirtualUser, MappingProviderError>;

        async fn enable_virtual_user<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<openstack_keystone_core_types::mapping::VirtualUser, MappingProviderError>;

        async fn authenticate_by_mapping(
            &self,
            state: &ServiceState,
            req: &openstack_keystone_core_types::mapping::auth::MappingAuthRequest,
        ) -> Result<AuthenticationResult, MappingProviderError>;
    }
}

// ==================== RoleApi Mock ====================

mock! {
    pub RoleProvider {}

    #[async_trait]
    impl RoleApi for RoleProvider {
        async fn create_role(
            &self,
            state: &ServiceState,
            params: openstack_keystone_core_types::role::RoleCreate,
        ) -> Result<openstack_keystone_core_types::role::Role, RoleProviderError>;

        async fn create_role_imply_rule<'a>(
            &self,
            state: &ServiceState,
            prior_role_id: &'a str,
            implied_role_id: &'a str,
        ) -> Result<openstack_keystone_core_types::role::RoleImply, RoleProviderError>;

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
            roles: &mut Vec<openstack_keystone_core_types::role::RoleRef>,
        ) -> Result<(), RoleProviderError>;

        async fn get_role<'a>(
            &self,
            state: &ServiceState,
            role_id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::role::Role>, RoleProviderError>;

        async fn get_role_imply_rule<'a>(
            &self,
            state: &ServiceState,
            prior_role_id: &'a str,
            implied_role_id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::role::RoleImply>, RoleProviderError>;

        async fn list_role_imply_rules(
            &self,
            state: &ServiceState,
        ) -> Result<Vec<openstack_keystone_core_types::role::RoleImply>, RoleProviderError>;

        async fn list_role_imply_rules_by_prior<'a>(
            &self,
            state: &ServiceState,
            prior_role_id: &'a str,
        ) -> Result<Vec<openstack_keystone_core_types::role::RoleImply>, RoleProviderError>;

        async fn list_roles(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::role::RoleListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::role::Role>, RoleProviderError>;
    }
}

// ==================== IdentityApi Mock ====================

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
            auth: &openstack_keystone_core_types::identity::UserPasswordAuthRequest,
        ) -> Result<AuthenticationResult, IdentityProviderError>;

        async fn create_group(
            &self,
            state: &ServiceState,
            group: openstack_keystone_core_types::identity::GroupCreate,
        ) -> Result<openstack_keystone_core_types::identity::Group, IdentityProviderError>;

        async fn create_service_account(
            &self,
            state: &ServiceState,
            sa: openstack_keystone_core_types::identity::ServiceAccountCreate,
        ) -> Result<openstack_keystone_core_types::identity::ServiceAccount, IdentityProviderError>;

        async fn create_user(
            &self,
            state: &ServiceState,
            user: openstack_keystone_core_types::identity::UserCreate,
        ) -> Result<openstack_keystone_core_types::identity::UserResponse, IdentityProviderError>;

        async fn delete_user<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<(), IdentityProviderError>;

        async fn get_group<'a>(
            &self,
            state: &ServiceState,
            group_id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::identity::Group>, IdentityProviderError>;

        async fn get_service_account<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::identity::ServiceAccount>, IdentityProviderError>;

        async fn get_user<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::identity::UserResponse>, IdentityProviderError>;

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
        ) -> Result<Option<openstack_keystone_core_types::identity::UserResponse>, IdentityProviderError>;

        async fn list_groups(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::identity::GroupListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::identity::Group>, IdentityProviderError>;

        async fn list_users(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::identity::UserListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::identity::UserResponse>, IdentityProviderError>;

        async fn delete_group<'a>(
            &self,
            state: &ServiceState,
            group_id: &'a str,
        ) -> Result<(), IdentityProviderError>;

        async fn list_groups_of_user<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<Vec<openstack_keystone_core_types::identity::Group>, IdentityProviderError>;

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
            group_ids: std::collections::HashSet<&'a str>,
        ) -> Result<(), IdentityProviderError>;

        async fn remove_user_from_groups_expiring<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
            group_ids: std::collections::HashSet<&'a str>,
            idp_id: &'a str,
        ) -> Result<(), IdentityProviderError>;

        async fn set_user_groups<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
            group_ids: std::collections::HashSet<&'a str>,
        ) -> Result<(), IdentityProviderError>;

        async fn update_user<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
            user: openstack_keystone_core_types::identity::UserUpdate,
        ) -> Result<openstack_keystone_core_types::identity::UserResponse, IdentityProviderError>;

        async fn update_user_password<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
            original_password: secrecy::SecretString,
            new_password: secrecy::SecretString,
        ) -> Result<(), IdentityProviderError>;

        async fn set_user_groups_expiring<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
            group_ids: std::collections::HashSet<&'a str>,
            idp_id: &'a str,
            last_verified: Option<&'a chrono::DateTime<chrono::Utc>>,
        ) -> Result<(), IdentityProviderError>;
    }
}

// ==================== ResourceApi Mock ====================

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
            domain: openstack_keystone_core_types::resource::DomainCreate,
        ) -> Result<openstack_keystone_core_types::resource::Domain, ResourceProviderError>;

        async fn create_project(
            &self,
            state: &ServiceState,
            project: openstack_keystone_core_types::resource::ProjectCreate,
        ) -> Result<openstack_keystone_core_types::resource::Project, ResourceProviderError>;

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
        ) -> Result<Option<openstack_keystone_core_types::resource::Domain>, ResourceProviderError>;

        async fn get_project<'a>(
            &self,
            state: &ServiceState,
            project_id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::resource::Project>, ResourceProviderError>;

        async fn get_project_by_name<'a>(
            &self,
            state: &ServiceState,
            name: &'a str,
            domain_id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::resource::Project>, ResourceProviderError>;

        async fn get_project_parents<'a>(
            &self,
            state: &ServiceState,
            project_id: &'a str,
        ) -> Result<Option<Vec<openstack_keystone_core_types::resource::Project>>, ResourceProviderError>;

        async fn find_domain_by_name<'a>(
            &self,
            state: &ServiceState,
            domain_name: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::resource::Domain>, ResourceProviderError>;

        async fn list_domains(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::resource::DomainListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::resource::Domain>, ResourceProviderError>;

        async fn list_projects(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::resource::ProjectListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::resource::Project>, ResourceProviderError>;
    }
}

// ==================== RevokeApi Mock ====================

mock! {
    pub RevokeProvider {}

    #[async_trait]
    impl RevokeApi for RevokeProvider {
        async fn create_revocation_event(
            &self,
            state: &ServiceState,
            event: openstack_keystone_core_types::revoke::RevocationEventCreate,
        ) -> Result<openstack_keystone_core_types::revoke::RevocationEvent, RevokeProviderError>;

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

// ==================== TokenApi Mock ====================

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

        async fn issue_token_context(
            &self,
            state: &ServiceState,
            ctx: &SecurityContext,
            scope: &CoreScopeInfo,
        ) -> Result<ValidatedSecurityContext, TokenProviderError>;

        fn encode_token(&self, token: &FernetToken) -> Result<String, TokenProviderError>;

        async fn get_token_restriction<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            expand_roles: bool,
        ) -> Result<Option<openstack_keystone_core_types::token::TokenRestriction>, TokenProviderError>;

        async fn create_token_restriction<'a>(
            &self,
            state: &ServiceState,
            restriction: openstack_keystone_core_types::token::TokenRestrictionCreate,
        ) -> Result<openstack_keystone_core_types::token::TokenRestriction, TokenProviderError>;

        async fn list_token_restrictions<'a>(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::token::TokenRestrictionListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::token::TokenRestriction>, TokenProviderError>;

        async fn update_token_restriction<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            restriction: openstack_keystone_core_types::token::TokenRestrictionUpdate,
        ) -> Result<openstack_keystone_core_types::token::TokenRestriction, TokenProviderError>;

        async fn delete_token_restriction<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<(), TokenProviderError>;
    }
}

// ==================== TrustApi Mock ====================

mock! {
    pub TrustProvider {}

    #[async_trait]
    impl TrustApi for TrustProvider {
        async fn get_trust<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::trust::Trust>, TrustProviderError>;

        async fn get_trust_delegation_chain<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<Vec<openstack_keystone_core_types::trust::Trust>>, TrustProviderError>;

        async fn list_trusts(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::trust::TrustListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::trust::Trust>, TrustProviderError>;

        async fn validate_trust_delegation_chain(
            &self,
            state: &ServiceState,
            trust: &openstack_keystone_core_types::trust::Trust,
        ) -> Result<bool, TrustProviderError>;
    }
}

// ==================== CatalogApi Mock ====================

mock! {
    pub CatalogProvider {}

    #[async_trait]
    impl CatalogApi for CatalogProvider {
        async fn create_endpoint(
            &self,
            state: &ServiceState,
            endpoint: openstack_keystone_core_types::catalog::EndpointCreate,
        ) -> Result<openstack_keystone_core_types::catalog::Endpoint, CatalogProviderError>;

        async fn create_region(
            &self,
            state: &ServiceState,
            region: openstack_keystone_core_types::catalog::RegionCreate,
        ) -> Result<openstack_keystone_core_types::catalog::Region, CatalogProviderError>;

        async fn create_service(
            &self,
            state: &ServiceState,
            service: openstack_keystone_core_types::catalog::ServiceCreate,
        ) -> Result<openstack_keystone_core_types::catalog::Service, CatalogProviderError>;

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
        ) -> Result<Vec<(openstack_keystone_core_types::catalog::Service, Vec<openstack_keystone_core_types::catalog::Endpoint>)>, CatalogProviderError>;

        async fn get_endpoint<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::catalog::Endpoint>, CatalogProviderError>;

        async fn get_region<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::catalog::Region>, CatalogProviderError>;

        async fn get_service<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::catalog::Service>, CatalogProviderError>;

        async fn list_endpoints(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::catalog::EndpointListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::catalog::Endpoint>, CatalogProviderError>;

        async fn list_regions(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::catalog::RegionListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::catalog::Region>, CatalogProviderError>;

        async fn list_services(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::catalog::ServiceListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::catalog::Service>, CatalogProviderError>;

        async fn update_endpoint<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            endpoint: openstack_keystone_core_types::catalog::EndpointUpdate,
        ) -> Result<openstack_keystone_core_types::catalog::Endpoint, CatalogProviderError>;

        async fn update_region<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            region: openstack_keystone_core_types::catalog::RegionUpdate,
        ) -> Result<openstack_keystone_core_types::catalog::Region, CatalogProviderError>;

        async fn update_service<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            service: openstack_keystone_core_types::catalog::ServiceUpdate,
        ) -> Result<openstack_keystone_core_types::catalog::Service, CatalogProviderError>;
    }
}

// ==================== FederationApi Mock ====================
// Note: use `auth_state` instead of `state` for the second parameter of create_auth_state
// to avoid name shadowing issues with mockall.

mock! {
    pub FederationProvider {}

    #[async_trait]
    impl FederationApi for FederationProvider {
        async fn cleanup(&self, state: &ServiceState) -> Result<(), FederationProviderError>;

        async fn create_identity_provider(
            &self,
            state: &ServiceState,
            idp: openstack_keystone_core_types::federation::IdentityProviderCreate,
        ) -> Result<openstack_keystone_core_types::federation::IdentityProvider, FederationProviderError>;

        async fn create_auth_state(
            &self,
            state: &ServiceState,
            auth_state: openstack_keystone_core_types::federation::AuthState,
        ) -> Result<openstack_keystone_core_types::federation::AuthState, FederationProviderError>;

        async fn create_mapping(
            &self,
            state: &ServiceState,
            mapping: openstack_keystone_core_types::federation::Mapping,
        ) -> Result<openstack_keystone_core_types::federation::Mapping, FederationProviderError>;

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

        async fn delete_mapping<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<(), FederationProviderError>;

        async fn get_auth_state<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::federation::AuthState>, FederationProviderError>;

        async fn get_identity_provider<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::federation::IdentityProvider>, FederationProviderError>;

        async fn get_mapping<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::federation::Mapping>, FederationProviderError>;

        async fn list_identity_providers(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::federation::IdentityProviderListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::federation::IdentityProvider>, FederationProviderError>;

        async fn list_mappings(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::federation::MappingListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::federation::Mapping>, FederationProviderError>;

        async fn update_identity_provider<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            idp: openstack_keystone_core_types::federation::IdentityProviderUpdate,
        ) -> Result<openstack_keystone_core_types::federation::IdentityProvider, FederationProviderError>;

        async fn update_mapping<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            mapping: openstack_keystone_core_types::federation::MappingUpdate,
        ) -> Result<openstack_keystone_core_types::federation::Mapping, FederationProviderError>;
    }
}

// ==================== IdMappingApi Mock ====================

mock! {
    pub IdMappingProvider {}

    #[async_trait]
    impl IdMappingApi for IdMappingProvider {
        async fn get_by_local_id<'a>(
            &self,
            state: &ServiceState,
            local_id: &'a str,
            domain_id: &'a str,
            entity_type: openstack_keystone_core_types::idmapping::IdMappingEntityType,
        ) -> Result<Option<openstack_keystone_core_types::idmapping::IdMapping>, IdMappingProviderError>;

        async fn get_by_public_id<'a>(
            &self,
            state: &ServiceState,
            public_id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::idmapping::IdMapping>, IdMappingProviderError>;
    }
}

// ==================== K8sAuthApi Mock ====================

mock! {
    pub K8sAuthProvider {}

    #[async_trait]
    impl K8sAuthApi for K8sAuthProvider {
        async fn authenticate_by_k8s_mapping(
            &self,
            state: &ServiceState,
            req: &openstack_keystone_core_types::k8s_auth::K8sAuthRequest,
        ) -> Result<AuthenticationResult, K8sAuthProviderError>;

        async fn create_auth_instance(
            &self,
            state: &ServiceState,
            config: openstack_keystone_core_types::k8s_auth::K8sAuthInstanceCreate,
        ) -> Result<openstack_keystone_core_types::k8s_auth::K8sAuthInstance, K8sAuthProviderError>;

        async fn delete_auth_instance<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<(), K8sAuthProviderError>;

        async fn get_auth_instance<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::k8s_auth::K8sAuthInstance>, K8sAuthProviderError>;

        async fn list_auth_instances(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::k8s_auth::K8sAuthInstanceListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::k8s_auth::K8sAuthInstance>, K8sAuthProviderError>;

        async fn update_auth_instance<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            data: openstack_keystone_core_types::k8s_auth::K8sAuthInstanceUpdate,
        ) -> Result<openstack_keystone_core_types::k8s_auth::K8sAuthInstance, K8sAuthProviderError>;
    }
}

// ==================== ApplicationCredentialApi Mock ====================

mock! {
    pub ApplicationCredentialProvider {}

    #[async_trait]
    impl ApplicationCredentialApi for ApplicationCredentialProvider {
        async fn create_application_credential(
            &self,
            state: &ServiceState,
            rec: openstack_keystone_core_types::application_credential::ApplicationCredentialCreate,
        ) -> Result<openstack_keystone_core_types::application_credential::ApplicationCredentialCreateResponse, ApplicationCredentialProviderError>;

        async fn get_application_credential<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<openstack_keystone_core_types::application_credential::ApplicationCredential>, ApplicationCredentialProviderError>;

        async fn list_application_credentials(
            &self,
            state: &ServiceState,
            params: &openstack_keystone_core_types::application_credential::ApplicationCredentialListParameters,
        ) -> Result<Vec<openstack_keystone_core_types::application_credential::ApplicationCredential>, ApplicationCredentialProviderError>;
    }
}
