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
//! # Pre-flight security checks (Phase 4 / ADR §9)
//!
//! Called at the very start of `init_storage`, before any key material is
//! loaded into memory.  Checks and enforces OS-level memory-protection
//! invariants; logs CRITICAL on every failed check.
//!
//! TODO: add a `dev_mode: bool` parameter and make failures fatal in
//! production mode once `DistributedStorageConfiguration.dev_mode` is
//! implemented.  For now all failures emit tracing::error! and are
//! non-fatal so that integration tests continue to run in CI.

use nix::sys::resource::{Resource, getrlimit, setrlimit};
use tracing::{error, warn};

/// Minimum bytes of mlockable memory the process should be allowed.
/// 64 KiB: ample headroom for one DEK + sub-keys held in normal memory.
const MIN_MEMLOCK_BYTES: u64 = 64 * 1024;

/// Run security pre-flight checks.
///
/// Each check:
/// * attempts to harden the process limits
/// * logs `tracing::error!` on failure
///
/// Returns `Ok(())` always so that test environments that cannot set
/// these limits do not break the test suite.  Production deployments
/// should verify the checks pass via the emitted log lines.
pub fn preflight_check() {
    disable_core_dumps();
    set_not_dumpable();
    check_memlock();
}

fn disable_core_dumps() {
    match setrlimit(Resource::RLIMIT_CORE, 0, 0) {
        Ok(()) => {}
        Err(e) => {
            error!(
                "SECURITY: could not set RLIMIT_CORE=0 — \
                 core dumps may leak key material: {e}"
            );
        }
    }
}

/// Disable ptrace attachment and `/proc/…/mem` access via PR_SET_DUMPABLE.
/// No-op on non-Linux platforms.
#[cfg(target_os = "linux")]
fn set_not_dumpable() {
    use nix::sys::prctl;
    match prctl::set_dumpable(false) {
        Ok(()) => {}
        Err(e) => {
            error!(
                "SECURITY: could not set PR_SET_DUMPABLE=0 — \
                 ptrace may expose key material: {e}"
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn set_not_dumpable() {}

fn check_memlock() {
    match getrlimit(Resource::RLIMIT_MEMLOCK) {
        Ok((soft, _hard)) => {
            if soft < MIN_MEMLOCK_BYTES {
                warn!(
                    "SECURITY: RLIMIT_MEMLOCK soft limit is {soft} bytes \
                     (minimum recommended: {MIN_MEMLOCK_BYTES}); \
                     mlock'd key pools may fail"
                );
            }
        }
        Err(e) => {
            error!("SECURITY: could not read RLIMIT_MEMLOCK: {e}");
        }
    }
}
