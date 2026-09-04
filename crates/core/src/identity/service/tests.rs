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

//! Unit tests for [`super::IdentityService`].
//!
//! Split out of `service.rs` to keep the implementation file short and the
//! test suites structurally isolated. Per-domain driver dispatch lives in the
//! [`per_domain_dispatch`] submodule.

use serde_json::json;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::credential::{Credential, CredentialBuilder};
use openstack_keystone_core_types::identity::{
    UserCreateBuilder, UserResponseBuilder, UserUpdateBuilder,
};

use super::*;
use crate::auth::ValidatedSecurityContext;
use crate::credential::MockCredentialProvider;
use crate::identity::backend::MockIdentityBackend;
use crate::provider::Provider;
use crate::resource::MockResourceProvider;
use crate::tests::get_mocked_state;
use openstack_keystone_core_types::auth::{
    AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalInfo, ScopeInfo,
    SecurityContext, UserIdentityInfoBuilder,
};
use openstack_keystone_core_types::resource::DomainBuilder as ResourceDomainBuilder;

fn make_vsc_scoped(scope: ScopeInfo) -> ValidatedSecurityContext {
    let user = UserIdentityInfoBuilder::default()
        .user_id("test-user-id".to_string())
        .build()
        .unwrap();
    let authz = AuthzInfoBuilder::default().scope(scope).build().unwrap();
    let sc = SecurityContext::test_build()
        .authentication_context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(user),
        })
        .authorization(authz)
        .build();
    ValidatedSecurityContext::test_new(sc)
}

fn make_domain(id: &str) -> openstack_keystone_core_types::resource::Domain {
    ResourceDomainBuilder::default()
        .id(id)
        .name(format!("{id}-name"))
        .enabled(true)
        .build()
        .unwrap()
}

fn get_config_with_password_regex(regex_str: &str) -> Config {
    let mut config = Config::default();
    config.security_compliance.password_regex = Some(regex_str.to_string());
    // Compile the regex as Config::load_all would do.
    config.security_compliance.compile_regex().unwrap();
    config
}

#[tokio::test]
async fn test_create_user() {
    let state = get_mocked_state(None, None).await;
    let mut backend = MockIdentityBackend::default();
    backend.expect_create_user().returning(|_, _| {
        Ok(UserResponseBuilder::default()
            .id("id")
            .domain_id("domain_id")
            .enabled(true)
            .name("name")
            .build()
            .unwrap())
    });
    let provider = IdentityService::from_driver(backend);

    assert_eq!(
        provider
            .create_user(
                &ExecutionContext::internal(&state),
                UserCreateBuilder::default()
                    .name("uname")
                    .domain_id("did")
                    .build()
                    .unwrap()
            )
            .await
            .unwrap(),
        UserResponseBuilder::default()
            .domain_id("domain_id")
            .enabled(true)
            .id("id")
            .name("name")
            .build()
            .unwrap()
    );
}

#[tokio::test]
async fn test_create_user_defaults_domain_id_from_scope() {
    // Real clients (tempest, python-openstackclient) omit `domain_id` on
    // user create and expect the server to infer it from the caller's
    // token scope, matching python-keystone. Regression test for the
    // 422 "missing field `domain_id`" compatibility gap.
    let state = get_mocked_state(None, None).await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_create_user()
        .withf(|_, user| user.domain_id.as_deref() == Some("scoped-did"))
        .returning(|_, _| {
            Ok(UserResponseBuilder::default()
                .id("id")
                .domain_id("scoped-did")
                .enabled(true)
                .name("uname")
                .build()
                .unwrap())
        });
    let provider = IdentityService::from_driver(backend);
    let vsc = make_vsc_scoped(ScopeInfo::Domain(make_domain("scoped-did")));
    let ctx = ExecutionContext::from_auth(&state, &vsc);

    let created = provider
        .create_user(
            &ctx,
            UserCreateBuilder::default().name("uname").build().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.domain_id, "scoped-did");
}

#[tokio::test]
async fn test_get_user() {
    let state = get_mocked_state(None, None).await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_get_user()
        .withf(|_, uid: &'_ str| uid == "uid")
        .returning(|_, _| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id("id")
                    .domain_id("domain_id")
                    .enabled(true)
                    .name("name")
                    .build()
                    .unwrap(),
            ))
        });
    let provider = IdentityService::from_driver(backend);

    assert_eq!(
        provider
            .get_user(&ExecutionContext::internal(&state), "uid")
            .await
            .unwrap()
            .expect("user should be there"),
        UserResponseBuilder::default()
            .domain_id("domain_id")
            .enabled(true)
            .id("id")
            .name("name")
            .build()
            .unwrap(),
    );
}

#[tokio::test]
async fn test_get_user_domain_id() {
    let state = get_mocked_state(None, None).await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_get_user_domain_id()
        .withf(|_, uid: &'_ str| uid == "uid")
        .times(2) // only 2 times
        .returning(|_, _| Ok("did".into()));
    backend
        .expect_get_user_domain_id()
        .withf(|_, uid: &'_ str| uid == "missing")
        .returning(|_, _| Err(IdentityProviderError::UserNotFound("missing".into())));
    let mut provider = IdentityService::from_driver(backend);
    provider.caching = true;

    assert_eq!(
        provider
            .get_user_domain_id(&ExecutionContext::internal(&state), "uid")
            .await
            .unwrap(),
        "did"
    );
    assert_eq!(
        provider
            .get_user_domain_id(&ExecutionContext::internal(&state), "uid")
            .await
            .unwrap(),
        "did",
        "second time data extracted from cache"
    );
    assert!(
        provider
            .get_user_domain_id(&ExecutionContext::internal(&state), "missing")
            .await
            .is_err()
    );
    provider.caching = false;
    assert_eq!(
        provider
            .get_user_domain_id(&ExecutionContext::internal(&state), "uid")
            .await
            .unwrap(),
        "did",
        "third time backend is again triggered causing total of 2 invocations"
    );
}

#[tokio::test]
async fn test_delete_user() {
    let mut credential_mock = MockCredentialProvider::default();
    credential_mock
        .expect_delete_credentials_for_user()
        .withf(|_, uid: &'_ str| uid == "uid")
        .returning(|_, _| Ok(()));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_credential(credential_mock)),
    )
    .await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_delete_user()
        .withf(|_, uid: &'_ str| uid == "uid")
        .returning(|_, _| Ok(()));
    let provider = IdentityService::from_driver(backend);

    assert!(
        provider
            .delete_user(&ExecutionContext::internal(&state), "uid")
            .await
            .is_ok()
    );
}

/// RFC 6238 Appendix B seed/passcode used across the TOTP tests below,
/// with an oversized `period` so the resulting HOTP counter (`now /
/// period`) stays `0` for the foreseeable future regardless of the
/// wall-clock time the test actually runs at.
fn totp_credential(user_id: &str) -> Credential {
    CredentialBuilder::default()
        .id("cred_id")
        .blob(
            json!({
                "seed": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                "digits": 8,
                "period": 10_000_000_000u64,
            })
            .to_string(),
        )
        .r#type("totp")
        .user_id(user_id)
        .build()
        .unwrap()
}

const TOTP_PASSCODE_COUNTER_0: &str = "84755224";

fn totp_user(user_id: &str, domain_id: &str, enabled: bool) -> UserResponse {
    UserResponseBuilder::default()
        .id(user_id)
        .domain_id(domain_id)
        .enabled(enabled)
        .name("uname")
        .build()
        .unwrap()
}

#[tokio::test]
async fn test_authenticate_by_totp_success_by_id() {
    let mut credential_mock = MockCredentialProvider::default();
    credential_mock
        .expect_list_credentials_for_user()
        .withf(|_, uid: &'_ str, r#type: &Option<&str>| uid == "uid" && *r#type == Some("totp"))
        .returning(|_, _, _| Ok(vec![totp_credential("uid")]));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_credential(credential_mock)),
    )
    .await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_check_user_exist()
        .withf(|_, id, name, domain| *id == Some("uid") && name.is_none() && domain.is_none())
        .returning(|_, _, _, _| Ok("uid".to_string()));
    backend
        .expect_get_user()
        .withf(|_, uid: &'_ str| uid == "uid")
        .returning(|_, _| Ok(Some(totp_user("uid", "did", true))));
    let provider = IdentityService::from_driver(backend);

    let result = provider
        .authenticate_by_totp(
            &ExecutionContext::internal(&state),
            &UserTotpAuthRequestBuilder::default()
                .id("uid")
                .passcode(TOTP_PASSCODE_COUNTER_0)
                .build()
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(result.context, AuthenticationContext::Totp);
    assert_eq!(result.principal.get_user_id(), "uid");
}

/// ADR-0022 Invariants 4 and 8 on the TOTP path: the per-user bucket is
/// keyed on the confirmed user ID and fires before any credential is
/// listed or passcode verified. The bucket is exhausted directly through
/// `check_user` (simulating a prior authentication attempt) so timing
/// cannot replenish it mid-test.
#[tokio::test]
async fn test_authenticate_by_totp_rate_limited() {
    let mut credential_mock = MockCredentialProvider::default();
    // Rejected before verification: credentials must never be listed.
    credential_mock.expect_list_credentials_for_user().times(0);
    let mut config = openstack_keystone_config::Config::default();
    config.rate_limit_user_auth = openstack_keystone_config::RateLimitSection {
        enabled: true,
        burst_size: 1,
        replenish_rate_per_second: 1,
    };
    let state = get_mocked_state(
        Some(config),
        Some(Provider::mocked_builder().mock_credential(credential_mock)),
    )
    .await;
    assert!(state.rate_limiters.check_user("uid").is_ok());

    let mut backend = MockIdentityBackend::default();
    backend
        .expect_check_user_exist()
        .returning(|_, _, _, _| Ok("uid".to_string()));
    // Rejected before the full user is ever loaded.
    backend.expect_get_user().times(0);
    let provider = IdentityService::from_driver(backend);

    let result = provider
        .authenticate_by_totp(
            &ExecutionContext::internal(&state),
            &UserTotpAuthRequestBuilder::default()
                .id("uid")
                .passcode(TOTP_PASSCODE_COUNTER_0)
                .build()
                .unwrap(),
        )
        .await;

    assert!(matches!(
        result,
        Err(IdentityProviderError::TooManyRequests { retry_after_secs }) if retry_after_secs >= 1
    ));
}

#[tokio::test]
async fn test_authenticate_by_totp_wrong_passcode() {
    let mut credential_mock = MockCredentialProvider::default();
    credential_mock
        .expect_list_credentials_for_user()
        .returning(|_, _, _| Ok(vec![totp_credential("uid")]));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_credential(credential_mock)),
    )
    .await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_check_user_exist()
        .returning(|_, _, _, _| Ok("uid".to_string()));
    backend
        .expect_get_user()
        .returning(|_, _| Ok(Some(totp_user("uid", "did", true))));
    let provider = IdentityService::from_driver(backend);

    let result = provider
        .authenticate_by_totp(
            &ExecutionContext::internal(&state),
            &UserTotpAuthRequestBuilder::default()
                .id("uid")
                .passcode("00000000")
                .build()
                .unwrap(),
        )
        .await;

    assert!(matches!(
        result,
        Err(IdentityProviderError::Authentication {
            source: AuthenticationError::TotpPasscodeInvalid
        })
    ));
}

#[tokio::test]
async fn test_authenticate_by_totp_no_credentials() {
    let mut credential_mock = MockCredentialProvider::default();
    credential_mock
        .expect_list_credentials_for_user()
        .returning(|_, _, _| Ok(vec![]));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_credential(credential_mock)),
    )
    .await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_check_user_exist()
        .returning(|_, _, _, _| Ok("uid".to_string()));
    backend
        .expect_get_user()
        .returning(|_, _| Ok(Some(totp_user("uid", "did", true))));
    let provider = IdentityService::from_driver(backend);

    let result = provider
        .authenticate_by_totp(
            &ExecutionContext::internal(&state),
            &UserTotpAuthRequestBuilder::default()
                .id("uid")
                .passcode(TOTP_PASSCODE_COUNTER_0)
                .build()
                .unwrap(),
        )
        .await;

    assert!(matches!(
        result,
        Err(IdentityProviderError::Authentication {
            source: AuthenticationError::TotpPasscodeInvalid
        })
    ));
}

#[tokio::test]
async fn test_authenticate_by_totp_user_disabled() {
    let mut credential_mock = MockCredentialProvider::default();
    credential_mock.expect_list_credentials_for_user().times(0);
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_credential(credential_mock)),
    )
    .await;
    let mut backend = MockIdentityBackend::default();
    // The cheap probe rejects the disabled account before any credential
    // work; the full user is never loaded.
    backend
        .expect_check_user_exist()
        .returning(|_, _, _, _| Err(AuthenticationError::UserDisabled("uid".into()).into()));
    backend.expect_get_user().times(0);
    let provider = IdentityService::from_driver(backend);

    let result = provider
        .authenticate_by_totp(
            &ExecutionContext::internal(&state),
            &UserTotpAuthRequestBuilder::default()
                .id("uid")
                .passcode(TOTP_PASSCODE_COUNTER_0)
                .build()
                .unwrap(),
        )
        .await;

    assert!(matches!(
        result,
        Err(IdentityProviderError::Authentication {
            source: AuthenticationError::UserDisabled(id)
        }) if id == "uid"
    ));
}

#[tokio::test]
async fn test_authenticate_by_totp_user_not_found() {
    let state = get_mocked_state(None, None).await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_check_user_exist()
        .returning(|_, _, _, _| Err(IdentityProviderError::UserNotFound("uid".into())));
    let provider = IdentityService::from_driver(backend);

    let result = provider
        .authenticate_by_totp(
            &ExecutionContext::internal(&state),
            &UserTotpAuthRequestBuilder::default()
                .id("uid")
                .passcode(TOTP_PASSCODE_COUNTER_0)
                .build()
                .unwrap(),
        )
        .await;

    assert!(matches!(
        result,
        Err(IdentityProviderError::Authentication {
            source: AuthenticationError::TotpPasscodeInvalid
        })
    ));
}

#[tokio::test]
async fn test_authenticate_by_totp_success_by_name_and_domain() {
    let mut credential_mock = MockCredentialProvider::default();
    credential_mock
        .expect_list_credentials_for_user()
        .withf(|_, uid: &'_ str, r#type: &Option<&str>| uid == "uid" && *r#type == Some("totp"))
        .returning(|_, _, _| Ok(vec![totp_credential("uid")]));
    let mut resource_mock = MockResourceProvider::default();
    resource_mock
        .expect_find_domain_by_name()
        .withf(|_, name: &'_ str| name == "dname")
        .returning(|_, _| {
            Ok(Some(openstack_keystone_core_types::resource::Domain {
                id: "did".into(),
                enabled: true,
                ..Default::default()
            }))
        });
    let state = get_mocked_state(
        None,
        Some(
            Provider::mocked_builder()
                .mock_credential(credential_mock)
                .mock_resource(resource_mock),
        ),
    )
    .await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_check_user_exist()
        .withf(|_, id, name, domain| {
            id.is_none() && *name == Some("uname_lookup") && *domain == Some("did")
        })
        .returning(|_, _, _, _| Ok("uid".to_string()));
    backend
        .expect_get_user()
        .withf(|_, uid: &'_ str| uid == "uid")
        .returning(|_, _| Ok(Some(totp_user("uid", "did", true))));
    let provider = IdentityService::from_driver(backend);

    let result = provider
        .authenticate_by_totp(
            &ExecutionContext::internal(&state),
            &UserTotpAuthRequestBuilder::default()
                .name("uname_lookup")
                .domain(DomainBuilder::default().name("dname").build().unwrap())
                .passcode(TOTP_PASSCODE_COUNTER_0)
                .build()
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(result.context, AuthenticationContext::Totp);
    assert_eq!(result.principal.get_user_id(), "uid");
}

/// ADR-0022 Invariants 4 and 8 at the provider level: the enabled
/// per-user bucket is keyed on the ID resolved by the cheap probe and
/// fires before the backend performs any password verification. The
/// bucket is exhausted directly through `check_user` (simulating a prior
/// attempt) so timing cannot replenish it mid-test.
#[tokio::test]
async fn test_authenticate_by_password_rate_limited() {
    let mut config = openstack_keystone_config::Config::default();
    config.rate_limit_user_auth = openstack_keystone_config::RateLimitSection {
        enabled: true,
        burst_size: 1,
        replenish_rate_per_second: 1,
    };
    let state = get_mocked_state(Some(config), None).await;
    assert!(state.rate_limiters.check_user("uid").is_ok());

    let mut backend = MockIdentityBackend::default();
    backend
        .expect_check_user_exist()
        .withf(|_, id, name, domain| *id == Some("uid") && name.is_none() && domain.is_none())
        .returning(|_, _, _, _| Ok("uid".to_string()));
    // The expensive backend authentication must never be reached.
    backend.expect_authenticate_by_password().times(0);
    let provider = IdentityService::from_driver(backend);

    let result = provider
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequest {
                id: Some("uid".into()),
                password: "pass".into(),
                ..Default::default()
            },
        )
        .await;

    assert!(matches!(
        result,
        Err(IdentityProviderError::TooManyRequests { retry_after_secs }) if retry_after_secs >= 1
    ));
}

/// ADR-0022 Invariant 8: unknown users never touch the limiter store.
/// The probe misses and the request falls through to the backend, which
/// keeps the uniform dummy-hash credentials error — never a 429 — no
/// matter how often it is retried.
#[tokio::test]
async fn test_authenticate_by_password_unknown_user_uniform_error() {
    let mut config = openstack_keystone_config::Config::default();
    config.rate_limit_user_auth = openstack_keystone_config::RateLimitSection {
        enabled: true,
        burst_size: 1,
        replenish_rate_per_second: 1,
    };
    let state = get_mocked_state(Some(config), None).await;

    let mut backend = MockIdentityBackend::default();
    backend
        .expect_check_user_exist()
        .returning(|_, _, _, _| Err(IdentityProviderError::UserNotFound("ghost".into())));
    backend
        .expect_authenticate_by_password()
        .times(2)
        .returning(|_, _| Err(AuthenticationError::UserNameOrPasswordWrong.into()));
    let provider = IdentityService::from_driver(backend);

    for _ in 0..2 {
        let result = provider
            .authenticate_by_password(
                &ExecutionContext::internal(&state),
                &UserPasswordAuthRequest {
                    id: Some("ghost".into()),
                    password: "pass".into(),
                    ..Default::default()
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(IdentityProviderError::Authentication {
                source: AuthenticationError::UserNameOrPasswordWrong
            })
        ));
    }
}

/// With the bucket disabled (the default), the probe is skipped
/// entirely: rate limiting adds no extra query to the authentication
/// hot path.
#[tokio::test]
async fn test_authenticate_by_password_probe_skipped_when_disabled() {
    let state = get_mocked_state(None, None).await;

    let mut backend = MockIdentityBackend::default();
    backend.expect_check_user_exist().times(0);
    backend
        .expect_authenticate_by_password()
        .once()
        .returning(|_, _| Err(AuthenticationError::UserNameOrPasswordWrong.into()));
    let provider = IdentityService::from_driver(backend);

    let result = provider
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequest {
                id: Some("uid".into()),
                password: "pass".into(),
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(
        result,
        Err(IdentityProviderError::Authentication {
            source: AuthenticationError::UserNameOrPasswordWrong
        })
    ));
}

/// Within quota the request proceeds to the backend normally.
#[tokio::test]
async fn test_authenticate_by_password_within_quota_reaches_backend() {
    let mut config = openstack_keystone_config::Config::default();
    config.rate_limit_user_auth = openstack_keystone_config::RateLimitSection {
        enabled: true,
        burst_size: 100,
        replenish_rate_per_second: 10,
    };
    let state = get_mocked_state(Some(config), None).await;

    let mut backend = MockIdentityBackend::default();
    backend
        .expect_check_user_exist()
        .returning(|_, _, _, _| Ok("uid".to_string()));
    backend
        .expect_authenticate_by_password()
        .once()
        .returning(|_, _| Err(AuthenticationError::UserNameOrPasswordWrong.into()));
    let provider = IdentityService::from_driver(backend);

    let result = provider
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequest {
                id: Some("uid".into()),
                password: "pass".into(),
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(
        result,
        Err(IdentityProviderError::Authentication {
            source: AuthenticationError::UserNameOrPasswordWrong
        })
    ));
}

/// Password regex rejects invalid password on user creation.
#[tokio::test]
async fn test_create_user_password_regex_rejected() {
    let config = get_config_with_password_regex(r"^.{7,}$");
    let state = get_mocked_state(Some(config), None).await;
    let provider = IdentityService::from_driver(MockIdentityBackend::default());

    let result = provider
        .create_user(
            &ExecutionContext::internal(&state),
            UserCreateBuilder::default()
                .name("uname")
                .domain_id("did")
                .password("short")
                .build()
                .unwrap(),
        )
        .await;

    assert!(
        matches!(result, Err(IdentityProviderError::SecurityCompliance(..))),
        "expected SecurityCompliance error for invalid password"
    );
}

/// Password regex accepts valid password on user creation and backend is
/// invoked.
#[tokio::test]
async fn test_create_user_password_regex_accepted() {
    let config = get_config_with_password_regex(r"^.{3,}$");
    let state = get_mocked_state(Some(config), None).await;
    let mut backend = MockIdentityBackend::default();
    backend.expect_create_user().returning(|_, _| {
        Ok(UserResponseBuilder::default()
            .id("id")
            .domain_id("domain_id")
            .enabled(true)
            .name("name")
            .build()
            .unwrap())
    });
    let provider = IdentityService::from_driver(backend);

    assert!(
        provider
            .create_user(
                &ExecutionContext::internal(&state),
                UserCreateBuilder::default()
                    .name("uname")
                    .domain_id("did")
                    .password("Abc1")
                    .build()
                    .unwrap(),
            )
            .await
            .is_ok(),
        "password matching regex should reach backend"
    );
}

/// No password on user creation skips validation and backend is invoked.
#[tokio::test]
async fn test_create_user_no_password() {
    let config = get_config_with_password_regex(r"^.{7,}$");
    let state = get_mocked_state(Some(config), None).await;
    let mut backend = MockIdentityBackend::default();
    backend.expect_create_user().returning(|_, _| {
        Ok(UserResponseBuilder::default()
            .id("id")
            .domain_id("domain_id")
            .enabled(true)
            .name("name")
            .build()
            .unwrap())
    });
    let provider = IdentityService::from_driver(backend);

    assert!(
        provider
            .create_user(
                &ExecutionContext::internal(&state),
                UserCreateBuilder::default()
                    .name("uname")
                    .domain_id("did")
                    .build()
                    .unwrap(),
            )
            .await
            .is_ok(),
        "no password should skip validation"
    );
}

/// Password regex rejects invalid password on user update.
#[tokio::test]
async fn test_update_user_password_regex_rejected() {
    let config = get_config_with_password_regex(r"^.{7,}$");
    let state = get_mocked_state(Some(config), None).await;
    let provider = IdentityService::from_driver(MockIdentityBackend::default());

    let result = provider
        .update_user(
            &ExecutionContext::internal(&state),
            "uid",
            UserUpdateBuilder::default()
                .password("short")
                .build()
                .unwrap(),
        )
        .await;

    assert!(
        matches!(result, Err(IdentityProviderError::SecurityCompliance(..))),
        "expected SecurityCompliance error for invalid password on update"
    );
}

/// Password regex accepts valid password on user update and backend is
/// invoked.
#[tokio::test]
async fn test_update_user_password_regex_accepted() {
    let config = get_config_with_password_regex(r"^.{3,}$");
    let state = get_mocked_state(Some(config), None).await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_update_user()
        .returning(|_, _: &'_ str, _: UserUpdate| {
            Ok(UserResponseBuilder::default()
                .id("id")
                .domain_id("domain_id")
                .enabled(true)
                .name("name")
                .build()
                .unwrap())
        });
    let provider = IdentityService::from_driver(backend);

    assert!(
        provider
            .update_user(
                &ExecutionContext::internal(&state),
                "uid",
                UserUpdateBuilder::default()
                    .password("Abc1")
                    .build()
                    .unwrap(),
            )
            .await
            .is_ok(),
        "password matching regex on update should reach backend"
    );
}

/// No password on user update skips validation and backend is invoked.
#[tokio::test]
async fn test_update_user_no_password() {
    let config = get_config_with_password_regex(r"^.{7,}$");
    let state = get_mocked_state(Some(config), None).await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_update_user()
        .returning(|_, _: &'_ str, _: UserUpdate| {
            Ok(UserResponseBuilder::default()
                .id("id")
                .domain_id("domain_id")
                .enabled(true)
                .name("name")
                .build()
                .unwrap())
        });
    let provider = IdentityService::from_driver(backend);

    assert!(
        provider
            .update_user(
                &ExecutionContext::internal(&state),
                "uid",
                UserUpdateBuilder::default()
                    .name("new_name")
                    .build()
                    .unwrap(),
            )
            .await
            .is_ok(),
        "no password on update should skip validation"
    );
}

// --- Per-request cache (ADR 0030) -------------------------------------

use openstack_keystone_core_types::identity::{GroupBuilder, GroupUpdate};

fn make_user(id: &str) -> UserResponse {
    UserResponseBuilder::default()
        .id(id)
        .domain_id("did")
        .enabled(true)
        .name(format!("{id}-name"))
        .build()
        .unwrap()
}

fn make_group(id: &str) -> Group {
    GroupBuilder::default()
        .id(id)
        .domain_id("did")
        .name(format!("{id}-name"))
        .build()
        .unwrap()
}

#[tokio::test]
async fn test_get_user_hits_backend_once_across_repeated_calls() {
    let state = get_mocked_state(None, None).await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_get_user()
        .times(1)
        .withf(|_, uid: &'_ str| uid == "uid")
        .returning(|_, _| Ok(Some(make_user("uid"))));
    let provider = IdentityService::from_driver(backend);

    crate::request_cache::RequestCache::scope(async {
        let ctx = ExecutionContext::internal(&state);
        let first = provider.get_user(&ctx, "uid").await.unwrap().unwrap();
        let second = provider.get_user(&ctx, "uid").await.unwrap().unwrap();
        assert_eq!(first, second);
    })
    .await;
}

#[tokio::test]
async fn test_get_user_not_cached_outside_request_scope() {
    let state = get_mocked_state(None, None).await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_get_user()
        .times(2)
        .withf(|_, uid: &'_ str| uid == "uid")
        .returning(|_, _| Ok(Some(make_user("uid"))));
    let provider = IdentityService::from_driver(backend);

    let ctx = ExecutionContext::internal(&state);
    provider.get_user(&ctx, "uid").await.unwrap();
    provider.get_user(&ctx, "uid").await.unwrap();
}

#[tokio::test]
async fn test_update_user_refreshes_cache_instead_of_refetching() {
    let state = get_mocked_state(None, None).await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_get_user()
        .times(1)
        .withf(|_, uid: &'_ str| uid == "uid")
        .returning(|_, _| Ok(Some(make_user("uid"))));
    backend
        .expect_update_user()
        .withf(|_, uid: &'_ str, _| uid == "uid")
        .returning(|_, _, update| {
            let mut u = make_user("uid");
            if let Some(name) = update.name {
                u.name = name;
            }
            Ok(u)
        });
    let provider = IdentityService::from_driver(backend);

    crate::request_cache::RequestCache::scope(async {
        let ctx = ExecutionContext::internal(&state);
        provider.get_user(&ctx, "uid").await.unwrap();

        let updated = provider
            .update_user(
                &ctx,
                "uid",
                UserUpdateBuilder::default()
                    .name("renamed".to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(updated.name, "renamed");

        let refetched = provider.get_user(&ctx, "uid").await.unwrap().unwrap();
        assert_eq!(refetched.name, "renamed");
    })
    .await;
}

#[tokio::test]
async fn test_delete_user_invalidates_cache() {
    let mut credential_mock = MockCredentialProvider::default();
    credential_mock
        .expect_delete_credentials_for_user()
        .withf(|_, uid: &'_ str| uid == "uid")
        .returning(|_, _| Ok(()));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_credential(credential_mock)),
    )
    .await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_get_user()
        .times(2)
        .withf(|_, uid: &'_ str| uid == "uid")
        .returning(|_, _| Ok(Some(make_user("uid"))));
    backend
        .expect_delete_user()
        .withf(|_, uid: &'_ str| uid == "uid")
        .returning(|_, _| Ok(()));
    let provider = IdentityService::from_driver(backend);

    crate::request_cache::RequestCache::scope(async {
        let ctx = ExecutionContext::internal(&state);
        provider.get_user(&ctx, "uid").await.unwrap();
        provider.delete_user(&ctx, "uid").await.unwrap();
        provider.get_user(&ctx, "uid").await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_update_user_password_invalidates_cache() {
    let state = get_mocked_state(None, None).await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_get_user()
        .times(2)
        .withf(|_, uid: &'_ str| uid == "uid")
        .returning(|_, _| Ok(Some(make_user("uid"))));
    backend
        .expect_update_user_password()
        .withf(|_, uid: &'_ str, _, _| uid == "uid")
        .returning(|_, _, _, _| Ok(()));
    let provider = IdentityService::from_driver(backend);

    crate::request_cache::RequestCache::scope(async {
        let ctx = ExecutionContext::internal(&state);
        provider.get_user(&ctx, "uid").await.unwrap();
        provider
            .update_user_password(
                &ctx,
                "uid",
                SecretString::from("orig".to_string()),
                SecretString::from("newpassword".to_string()),
            )
            .await
            .unwrap();
        // `update_user_password` doesn't return a fresh `UserResponse`
        // to refresh the cache with -- the cached entry must instead be
        // invalidated so `password_expires_at` isn't served stale.
        provider.get_user(&ctx, "uid").await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_get_group_hits_backend_once_across_repeated_calls() {
    let state = get_mocked_state(None, None).await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_get_group()
        .times(1)
        .withf(|_, gid: &'_ str| gid == "gid")
        .returning(|_, _| Ok(Some(make_group("gid"))));
    let provider = IdentityService::from_driver(backend);

    crate::request_cache::RequestCache::scope(async {
        let ctx = ExecutionContext::internal(&state);
        let first = provider.get_group(&ctx, "gid").await.unwrap().unwrap();
        let second = provider.get_group(&ctx, "gid").await.unwrap().unwrap();
        assert_eq!(first, second);
    })
    .await;
}

#[tokio::test]
async fn test_get_group_not_cached_outside_request_scope() {
    let state = get_mocked_state(None, None).await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_get_group()
        .times(2)
        .withf(|_, gid: &'_ str| gid == "gid")
        .returning(|_, _| Ok(Some(make_group("gid"))));
    let provider = IdentityService::from_driver(backend);

    let ctx = ExecutionContext::internal(&state);
    provider.get_group(&ctx, "gid").await.unwrap();
    provider.get_group(&ctx, "gid").await.unwrap();
}

#[tokio::test]
async fn test_update_group_refreshes_cache_instead_of_refetching() {
    let state = get_mocked_state(None, None).await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_get_group()
        .times(1)
        .withf(|_, gid: &'_ str| gid == "gid")
        .returning(|_, _| Ok(Some(make_group("gid"))));
    backend
        .expect_update_group()
        .withf(|_, gid: &'_ str, _| gid == "gid")
        .returning(|_, _, update| {
            let mut g = make_group("gid");
            if let Some(name) = update.name {
                g.name = name;
            }
            Ok(g)
        });
    let provider = IdentityService::from_driver(backend);

    crate::request_cache::RequestCache::scope(async {
        let ctx = ExecutionContext::internal(&state);
        provider.get_group(&ctx, "gid").await.unwrap();

        let updated = provider
            .update_group(
                &ctx,
                "gid",
                GroupUpdate {
                    name: Some("renamed".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.name, "renamed");

        let refetched = provider.get_group(&ctx, "gid").await.unwrap().unwrap();
        assert_eq!(refetched.name, "renamed");
    })
    .await;
}

#[tokio::test]
async fn test_delete_group_invalidates_cache() {
    let state = get_mocked_state(None, None).await;
    let mut backend = MockIdentityBackend::default();
    backend
        .expect_get_group()
        .times(2)
        .withf(|_, gid: &'_ str| gid == "gid")
        .returning(|_, _| Ok(Some(make_group("gid"))));
    backend
        .expect_delete_group()
        .withf(|_, gid: &'_ str| gid == "gid")
        .returning(|_, _| Ok(()));
    let provider = IdentityService::from_driver(backend);

    crate::request_cache::RequestCache::scope(async {
        let ctx = ExecutionContext::internal(&state);
        provider.get_group(&ctx, "gid").await.unwrap();
        provider.delete_group(&ctx, "gid").await.unwrap();
        provider.get_group(&ctx, "gid").await.unwrap();
    })
    .await;
}

#[path = "tests/per_domain_dispatch.rs"]
mod per_domain_dispatch;
