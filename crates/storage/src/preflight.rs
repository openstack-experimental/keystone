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
//! # Pre-flight security checks (ADR 0016-v2 §9 / §12)
//!
//! Called at the very start of `init_storage`, before any key material is
//! loaded into memory.  Checks and enforces OS-level memory-protection
//! invariants; logs `CRITICAL` (`tracing::error!`) on every failed check.
//!
//! ## Production vs. development behaviour
//!
//! Pass `dev_mode = false` (the production default) to make failures **fatal**:
//! the node refuses to start if any check fails, satisfying ADR 0016-v2 §9
//! invariant 12.
//!
//! Pass `dev_mode = true` to relax the checks to non-fatal warnings so that
//! CI and developer workstations — which commonly cannot raise `RLIMIT_MEMLOCK`
//! or set `PR_SET_DUMPABLE` — can still run the storage stack.

use nix::sys::resource::{Resource, getrlimit, setrlimit};
use tracing::error;

/// Minimum bytes of mlockable memory the process should be allowed.
/// 64 KiB: ample headroom for one DEK + sub-keys held in normal memory.
const MIN_MEMLOCK_BYTES: u64 = 64 * 1024;

/// Run security pre-flight checks.
///
/// In **production mode** (`dev_mode = false`) any failed check causes this
/// function to return an `Err` containing a summary of all failures, and the
/// caller (`init_storage`) must treat this as a fatal startup error (ADR
/// 0016-v2 §9 / §12).
///
/// In **development mode** (`dev_mode = true`) failures are logged at
/// `error!` level but `Ok(())` is always returned so that CI environments
/// and developer workstations that cannot set strict OS limits are not broken.
pub fn preflight_check(dev_mode: bool) -> Result<(), String> {
    let mut failures: Vec<String> = Vec::new();

    if let Err(msg) = check_core_dumps() {
        error!("SECURITY: {msg}");
        failures.push(msg);
    }

    if let Err(msg) = check_dumpable() {
        error!("SECURITY: {msg}");
        failures.push(msg);
    }

    if let Err(msg) = check_memlock() {
        error!("SECURITY: {msg}");
        failures.push(msg);
    }

    if !dev_mode && !failures.is_empty() {
        return Err(format!(
            "startup pre-flight failed ({} check(s)); refusing to start in production mode: {}",
            failures.len(),
            failures.join("; ")
        ));
    }

    Ok(())
}

/// Attempt to set `RLIMIT_CORE = 0` to disable core dumps.
fn check_core_dumps() -> Result<(), String> {
    setrlimit(Resource::RLIMIT_CORE, 0, 0)
        .map_err(|e| format!("could not set RLIMIT_CORE=0 — core dumps may leak key material: {e}"))
}

/// Disable ptrace attachment and `/proc/…/mem` access via `PR_SET_DUMPABLE`.
/// No-op on non-Linux platforms (returns `Ok`).
#[cfg(target_os = "linux")]
fn check_dumpable() -> Result<(), String> {
    use nix::sys::prctl;
    prctl::set_dumpable(false).map_err(|e| {
        format!("could not set PR_SET_DUMPABLE=0 — ptrace may expose key material: {e}")
    })
}

#[cfg(not(target_os = "linux"))]
fn check_dumpable() -> Result<(), String> {
    Ok(())
}

/// Verify that the process has enough mlockable memory headroom.
fn check_memlock() -> Result<(), String> {
    let (soft, _hard) = getrlimit(Resource::RLIMIT_MEMLOCK)
        .map_err(|e| format!("could not read RLIMIT_MEMLOCK: {e}"))?;

    if soft < MIN_MEMLOCK_BYTES {
        return Err(format!(
            "RLIMIT_MEMLOCK soft limit is {soft} bytes \
             (minimum recommended: {MIN_MEMLOCK_BYTES}); \
             mlock'd key pools may fail at runtime"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_mode_never_fails() {
        // In dev mode the function must always return Ok regardless of the
        // outcome of individual OS checks (CI environments may not permit
        // the required resource-limit changes).
        let result = preflight_check(true);
        assert!(result.is_ok(), "dev_mode=true must not fail: {result:?}");
    }
}
