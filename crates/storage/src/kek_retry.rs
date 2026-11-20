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
//! Retrying DEK unwrap for paths that must not give up.
//!
//! Applying a replicated `InstallDek` entry, or a snapshot or restore, has to
//! end the same way on every node. When the KEK lives in a remote key store
//! (OpenBao Transit) that is briefly unreachable, aborting the state machine
//! would stop the node for a recoverable outage; waiting does not diverge it.
//! Only failures that are not transient (wrong key, corrupt blob) are
//! returned.

use std::time::Duration;

use openstack_keystone_storage_crypto::{CryptoError, KekProvider};
use zeroize::Zeroizing;

const FIRST_DELAY: Duration = Duration::from_millis(250);
const MAX_DELAY: Duration = Duration::from_secs(30);
/// After this long the retry is logged at `error` so an outage is not missed.
const LOUD_AFTER: Duration = Duration::from_secs(300);

/// [`KekProvider::unwrap_dek`], repeated with a capped exponential backoff
/// for as long as the failure is [transient](CryptoError::is_transient).
pub(crate) async fn unwrap_dek_retrying(
    kek: &dyn KekProvider,
    wrapped: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    unwrap_with_backoff(kek, wrapped, FIRST_DELAY, MAX_DELAY).await
}

async fn unwrap_with_backoff(
    kek: &dyn KekProvider,
    wrapped: &[u8],
    first_delay: Duration,
    max_delay: Duration,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut delay = first_delay;
    let started = tokio::time::Instant::now();
    loop {
        match kek.unwrap_dek(wrapped).await {
            Err(e) if e.is_transient() => {
                if started.elapsed() >= LOUD_AFTER {
                    tracing::error!(error = %e, waited = ?started.elapsed(), retry_in = ?delay, "KEK still unavailable; DEK unwrap is blocked");
                } else {
                    tracing::warn!(error = %e, retry_in = ?delay, "KEK unavailable; retrying DEK unwrap");
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(max_delay);
            }
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    struct Flaky {
        failures: AtomicU32,
        permanent: bool,
    }

    #[async_trait::async_trait]
    impl KekProvider for Flaky {
        async fn unwrap_dek(&self, _: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
            if self.failures.fetch_add(1, Ordering::SeqCst) < 2 {
                return Err(if self.permanent {
                    CryptoError::AesDecrypt
                } else {
                    CryptoError::KekUnavailable("down".into())
                });
            }
            Ok(Zeroizing::new([7u8; 32]))
        }

        async fn wrap_dek(&self, _: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
            Err(CryptoError::Rng)
        }
    }

    #[tokio::test]
    async fn transient_failures_are_retried() {
        let kek = Flaky {
            failures: AtomicU32::new(0),
            permanent: false,
        };
        let dek = unwrap_with_backoff(
            &kek,
            b"x",
            Duration::from_millis(1),
            Duration::from_millis(4),
        )
        .await
        .expect("unwrap");
        assert_eq!(*dek, [7u8; 32]);
        assert_eq!(kek.failures.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn permanent_failures_are_returned() {
        let kek = Flaky {
            failures: AtomicU32::new(0),
            permanent: true,
        };
        assert!(
            unwrap_with_backoff(
                &kek,
                b"x",
                Duration::from_millis(1),
                Duration::from_millis(4)
            )
            .await
            .is_err()
        );
        assert_eq!(kek.failures.load(Ordering::SeqCst), 1);
    }
}
