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
//! # WebAuthN extension REST API

use axum::Router;
use secrecy::ExposeSecret;
use std::sync::Arc;
use std::time::Duration;
use tokio::{spawn, time};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use webauthn_rs::WebauthnBuilder;
use webauthn_rs::fake::{FakePasskeyDistribution, WebauthnFakeCredentialGenerator};

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::error::KeystoneError;
use openstack_keystone_core::keystone::ServiceState;

mod auth;
pub mod hook;
mod register;
pub mod types;

pub use crate::api::auth::finish::verify_assertion;
pub use crate::api::auth::start::start_challenge;
use crate::api::hook::WebauthnHook;
use crate::api::types::{CombinedExtensionState, ExtensionState};
use crate::{WebauthnApi, WebauthnError, driver::*};

/// The storage slot of a pending authentication challenge.
///
/// The public `/v4/auth/passkey` flow (`ceremony = None`) keeps one slot per
/// user, so any `start` call for the user replaces the pending challenge.
/// A caller that runs its own ceremony, like the OAuth2 provider's second
/// factor step, passes a `ceremony` secret it holds (the pre-auth session
/// or device code) and gets a slot nobody else can overwrite or consume. Only
/// a digest of the secret is stored.
pub fn auth_state_slot(user_id: &str, ceremony: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    match ceremony {
        None => user_id.to_string(),
        Some(c) => format!(
            "{user_id}#{}",
            data_encoding::HEXLOWER.encode(&Sha256::digest(c.as_bytes()))
        ),
    }
}

/// OpenApi specification for the user passkey support.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name="passkey", description=r#"Passkey API."#),
    )
)]
pub struct ApiDoc;

/// OpenAPI router.
///
/// # Returns
/// An `OpenApiRouter` instance.
pub fn openapi_router() -> OpenApiRouter<CombinedExtensionState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .nest("/auth/passkey", auth::openapi_router())
        .nest("/users/{user_id}/passkeys", register::openapi_router())
}

/// Initialize the extension state.
///
/// # Parameters
/// - `main_state`: The core service state.
/// - `cancellation_token`: Token used to cancel background tasks.
///
/// # Returns
/// A `Result` containing the `CombinedExtensionState` on success, or a
/// `KeystoneError`.
pub async fn init_extension_state(
    main_state: ServiceState,
    cancellation_token: CancellationToken,
) -> Result<CombinedExtensionState, KeystoneError> {
    // Url containing the effective domain name
    // MUST include the port number!
    let config = main_state
        .config_manager
        .config
        .read()
        .await
        .webauthn
        .clone();
    let rp = config
        .relying_party
        .as_ref()
        .ok_or(WebauthnError::RelyingPartyConfigurationUnset)?;

    let mut builder = WebauthnBuilder::new(&rp.id, &rp.origin).map_err(WebauthnError::from)?;

    // Now, with the builder you can define other options.
    // Set a "nice" relying party name. Has no security properties and
    // may be changed in the future.
    if let Some(name) = &rp.name {
        builder = builder.rp_name(name);
    }

    // Consume the builder and create our webauthn instance.
    let webauthn = builder.build().map_err(WebauthnError::from)?;

    let driver: Box<dyn WebauthnApi> = match config.driver.as_str() {
        "sql" => Box::new(SqlDriver::default()),
        "raft" => Box::new(RaftDriver::default()),
        other => return Err(WebauthnError::UnsupportedDriver(other.to_string()))?,
    };
    let fake_credential_hmac_key: Vec<u8> = match &config.fake_credential_hmac_key {
        Some(key) => key.expose_secret().as_bytes().to_vec(),
        None => {
            warn!(
                "`[webauthn]fake_credential_hmac_key` is not configured; using a random \
                 per-process key for decoy credential IDs. Configure a stable key to keep user \
                 enumeration prevention effective across restarts and in multi-node deployments."
            );
            WebauthnFakeCredentialGenerator::<FakePasskeyDistribution>::new_hmac_key()
                .map_err(WebauthnError::from)?
        }
    };
    let fake_credential_generator = WebauthnFakeCredentialGenerator::new(&fake_credential_hmac_key)
        .map_err(WebauthnError::from)?;

    let extension_state = Arc::new(ExtensionState {
        provider: driver,
        webauthn,
        fake_credential_generator,
    });

    let combined_state = CombinedExtensionState {
        core: main_state,
        extension: extension_state,
    };
    combined_state
        .core
        .event_dispatcher
        .subscribe(Arc::new(WebauthnHook::new(combined_state.clone())))
        .await;
    spawn(cleanup(cancellation_token, combined_state.clone()));
    Ok(combined_state)
}

/// Whether `user_id` has at least one registered passkey.
pub async fn user_has_passkeys(
    state: &CombinedExtensionState,
    user_id: &str,
) -> Result<bool, KeystoneError> {
    Ok(!state
        .extension
        .provider
        .list_user_webauthn_credentials(&ExecutionContext::internal(&state.core), user_id)
        .await?
        .is_empty())
}

/// Router of the extension API bound to an already initialized state.
pub fn extension_router(combined_state: CombinedExtensionState) -> Router {
    let (router, _openapi) = OpenApiRouter::new()
        .merge(openapi_router())
        .with_state(combined_state)
        .split_for_parts();
    router
}

/// Initialize the extension.
///
/// # Parameters
/// - `main_state`: The core service state.
/// - `cancellation_token`: Token used to cancel background tasks.
///
/// # Returns
/// A `Result` containing the `Router` on success, or a `KeystoneError`.
pub async fn init_extension(
    main_state: ServiceState,
    cancellation_token: CancellationToken,
) -> Result<Router, KeystoneError> {
    let combined_state = init_extension_state(main_state, cancellation_token).await?;
    Ok(extension_router(combined_state))
}

/// Periodic cleanup job.
///
/// # Parameters
/// - `cancel`: Token used to cancel the cleanup task.
/// - `state`: The combined extension state.
async fn cleanup(cancel: CancellationToken, state: CombinedExtensionState) {
    let mut interval = time::interval(Duration::from_secs(60));
    interval.tick().await;
    info!("Start the periodic cleanup thread of the webauthn extension");
    loop {
        tokio::select! {
            _ = interval.tick() => {
                trace!("cleanup job tick");
                if let Err(e) = state.extension.provider.cleanup(&ExecutionContext::internal(&state.core)).await {
                    error!("Error during cleanup job: {}", e);
                }
            },
            () = cancel.cancelled() => {
                info!("Cancellation requested. Stopping webauthn cleanup task.");
                break; // Exit the loop
            }
        }
    }
}

#[cfg(test)]
mod slot_tests {
    use super::auth_state_slot;

    #[test]
    fn test_auth_state_slot() {
        // The public flow keeps the per-user slot.
        assert_eq!(auth_state_slot("u1", None), "u1");
        let a = auth_state_slot("u1", Some("session-a"));
        assert_ne!(a, auth_state_slot("u1", Some("session-b")));
        assert_ne!(a, auth_state_slot("u2", Some("session-a")));
        assert_eq!(a, auth_state_slot("u1", Some("session-a")));
        // Only a digest of the secret is stored.
        assert!(!a.contains("session-a"));
    }
}
