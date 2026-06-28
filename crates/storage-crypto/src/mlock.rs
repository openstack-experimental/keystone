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
//! Page-locked memory for cryptographic key material (ADR §9).
//!
//! [`LockedKey`] wraps a custom guard-paged allocation built on [`nix`] and
//! [`std::alloc`], providing:
//! - **Guard pages** (`PROT_NONE`) on both sides to catch buffer overruns.
//! - **`mlock`** to prevent the key page from being swapped to disk.
//! - **`madvise(MADV_DONTDUMP)`** to exclude the page from core dumps (Linux).
//! - **`madvise(MADV_DONTFORK)`** to prevent key exposure in child processes
//!   (Linux).
//! - **Canary** checked on `drop` to detect heap corruption.
//! - **Automatic zeroing** on `drop` via [`zeroize`].
//!
//! ## Page layout
//!
//! ```text
//! base_ptr:
//!   [0 .. PAGE_SIZE)                       metadata (unprotected_size), PROT_READ
//!   [PAGE_SIZE .. 2*PAGE_SIZE)             lower guard page, PROT_NONE
//!   [2*PAGE_SIZE .. 2*PAGE_SIZE+unprotected_size)
//!     within data: [padding | canary(16 B) | key(32 B)]
//!                   key is placed at the top of the page
//!   [2*PAGE_SIZE+unprotected_size ..)      upper guard page, PROT_NONE
//! ```
//!
//! # Why `#[allow(unsafe_code)]`
//!
//! This module requires unsafe code for three reasons that cannot be abstracted
//! away:
//! 1. `unsafe impl Send + Sync` are mandatory for any type that wraps a raw
//!    pointer.
//! 2. Page-aligned allocation and deallocation use `std::alloc`.
//! 3. `NonNull::as_ref` / `as_mut` dereference a raw pointer.
//!
//! All other workspace crates are subject to `unsafe_code = "forbid"`.

use std::alloc::{Layout, alloc, dealloc};
use std::process::abort;
use std::ptr::{self, NonNull};
use std::sync::OnceLock;

use nix::sys::mman::{MmapAdvise, ProtFlags, madvise, mlock, mprotect, munlock};
use nix::unistd::{SysconfVar, sysconf};
use rand::RngExt;
use zeroize::Zeroize;

/// Key size in bytes.
const KEY_SIZE: usize = 32;
/// Random canary placed immediately before the key; validated on free.
const CANARY_SIZE: usize = 16;

struct AllocState {
    page_size: usize,
    canary: [u8; CANARY_SIZE],
}

static ALLOC_STATE: OnceLock<AllocState> = OnceLock::new();

#[allow(clippy::expect_used)]
fn alloc_state() -> &'static AllocState {
    ALLOC_STATE.get_or_init(|| {
        let page_size = sysconf(SysconfVar::PAGE_SIZE)
            .expect("sysconf(PAGE_SIZE) failed")
            .expect("sysconf(PAGE_SIZE) returned None") as usize;
        assert!(
            page_size.is_power_of_two() && page_size >= CANARY_SIZE + KEY_SIZE,
            "page size {page_size} too small for guard-page allocation"
        );
        let mut canary = [0u8; CANARY_SIZE];
        rand::rng().fill(&mut canary);
        AllocState { page_size, canary }
    })
}

/// 32-byte key buffer backed by guard-paged, mlock'd memory.
///
/// Backed by a custom allocator that surrounds the key page with two
/// `PROT_NONE` guard pages.  The key page is `mlock`'d (preventing swap) and
/// marked `MADV_DONTDUMP` on Linux so it does not appear in core dumps.
/// On drop: canary is validated, memory is zeroed via [`zeroize`], unlocked,
/// and freed.
pub struct LockedKey {
    raw: NonNull<[u8; KEY_SIZE]>,
}

#[allow(unsafe_code)]
unsafe impl Send for LockedKey {}
#[allow(unsafe_code)]
unsafe impl Sync for LockedKey {}

#[allow(unsafe_code)]
impl LockedKey {
    /// Allocate a guard-paged key buffer, zeroed.
    ///
    /// Returns `Err` on allocation failure, `mprotect` refusal, or `mlock`
    /// failure.  `mlock` failure is treated as fatal: a node that cannot pin
    /// key material in RAM must not start, because un-locked pages may be
    /// swapped to disk and persist after process exit (ADR §9, Invariant 8).
    pub fn alloc() -> Result<Self, &'static str> {
        unsafe { locked_alloc() }
            .map(|mut raw| {
                // Zero the garbage-filled allocation before exposing it.
                unsafe { raw.as_mut().fill(0) };
                Self { raw }
            })
            .ok_or("guard-page allocation failed")
    }

    /// Copy `bytes` into a fresh guard-paged allocation.
    ///
    /// Panics on OOM; allocation failure for key material is fatal.
    #[allow(clippy::expect_used)]
    pub fn from_raw(bytes: [u8; KEY_SIZE]) -> Self {
        let mut key = Self::alloc().expect("OOM allocating LockedKey");
        key.as_mut().copy_from_slice(&bytes);
        key
    }

    /// Read access to the key bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        unsafe { self.raw.as_ref() }
    }

    /// Mutable access to the key bytes.
    #[allow(clippy::should_implement_trait)]
    #[inline]
    pub fn as_mut(&mut self) -> &mut [u8; KEY_SIZE] {
        unsafe { self.raw.as_mut() }
    }
}

#[allow(unsafe_code)]
impl Drop for LockedKey {
    fn drop(&mut self) {
        unsafe { locked_free(self.raw) }
    }
}

// ---------------------------------------------------------------------------
// Allocation internals
// ---------------------------------------------------------------------------

#[allow(unsafe_code)]
unsafe fn locked_alloc() -> Option<NonNull<[u8; KEY_SIZE]>> {
    let s = alloc_state();
    let page_size = s.page_size;
    let page_mask = page_size - 1;

    // CANARY_SIZE + KEY_SIZE = 48; round up to one page on all common platforms.
    let size_with_canary = CANARY_SIZE + KEY_SIZE;
    let unprotected_size = (size_with_canary + page_mask) & !page_mask;
    let total_size = page_size * 2 + unprotected_size + page_size; // 4 pages

    let layout = Layout::from_size_align(total_size, page_size).ok()?;

    // SAFETY: layout is non-zero and power-of-two aligned.
    let base_ptr = unsafe { alloc(layout) };
    if base_ptr.is_null() {
        return None;
    }

    // Data page starts after metadata page + lower guard.
    // SAFETY: offset is within the allocation bounds.
    let unprotected_ptr = unsafe { base_ptr.add(page_size * 2) };

    // Lower guard page.
    // SAFETY: base_ptr+page_size is within the allocation.
    if unsafe {
        mprotect(
            NonNull::new_unchecked(base_ptr.add(page_size).cast()),
            page_size,
            ProtFlags::PROT_NONE,
        )
    }
    .is_err()
    {
        unsafe { dealloc(base_ptr, layout) };
        return None;
    }

    // Upper guard page.
    // SAFETY: unprotected_ptr+unprotected_size is within the allocation.
    if unsafe {
        mprotect(
            NonNull::new_unchecked(unprotected_ptr.add(unprotected_size).cast()),
            page_size,
            ProtFlags::PROT_NONE,
        )
    }
    .is_err()
    {
        // Restore all pages to writable before freeing.
        unsafe {
            let _ = mprotect(
                NonNull::new_unchecked(base_ptr.cast()),
                total_size,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            );
            dealloc(base_ptr, layout);
        }
        return None;
    }

    // mlock — required; fail if the kernel refuses to pin the key page.
    // A node that cannot mlock key material must not start: un-locked pages
    // may be swapped to disk (ADR §9, Invariant 8).
    if unsafe {
        mlock(
            NonNull::new_unchecked(unprotected_ptr.cast()),
            unprotected_size,
        )
    }
    .is_err()
    {
        unsafe {
            let _ = mprotect(
                NonNull::new_unchecked(base_ptr.cast()),
                total_size,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            );
            dealloc(base_ptr, layout);
        }
        return None;
    }

    // Linux: exclude from core dumps and child processes via fork(2).
    #[cfg(target_os = "linux")]
    unsafe {
        let _ = madvise(
            NonNull::new_unchecked(unprotected_ptr.cast()),
            unprotected_size,
            MmapAdvise::MADV_DONTDUMP,
        );
        let _ = madvise(
            NonNull::new_unchecked(unprotected_ptr.cast()),
            unprotected_size,
            MmapAdvise::MADV_DONTFORK,
        );
    }

    // Canary + key are placed at the top of the data page:
    //   [padding ... | canary(16) | key(32)]
    // SAFETY: offsets are within the data page.
    let (canary_ptr, user_ptr) = unsafe {
        let cp = unprotected_ptr.add(unprotected_size - size_with_canary);
        (cp, cp.add(CANARY_SIZE))
    };

    unsafe {
        // Write canary.
        ptr::copy_nonoverlapping(s.canary.as_ptr(), canary_ptr, CANARY_SIZE);
        // Store unprotected_size in the metadata page.
        ptr::write_unaligned(base_ptr.cast::<usize>(), unprotected_size);
    }

    // Make the metadata page read-only.
    if unsafe {
        mprotect(
            NonNull::new_unchecked(base_ptr.cast()),
            page_size,
            ProtFlags::PROT_READ,
        )
    }
    .is_err()
    {
        unsafe {
            let _ = mprotect(
                NonNull::new_unchecked(base_ptr.cast()),
                total_size,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            );
            let _ = munlock(
                NonNull::new_unchecked(unprotected_ptr.cast()),
                unprotected_size,
            );
            dealloc(base_ptr, layout);
        }
        return None;
    }

    // Fill key region with garbage; caller must overwrite before use.
    unsafe { ptr::write_bytes(user_ptr, 0xd0, KEY_SIZE) };

    Some(unsafe { NonNull::new_unchecked(user_ptr.cast()) })
}

#[allow(unsafe_code)]
unsafe fn locked_free(ptr: NonNull<[u8; KEY_SIZE]>) {
    let s = alloc_state();
    let page_size = s.page_size;
    let page_mask = page_size - 1;

    // SAFETY: ptr was returned by locked_alloc; the layout is known and valid.
    let (user_ptr, canary_ptr, unprotected_ptr, base_ptr) = unsafe {
        let up = ptr.as_ptr().cast::<u8>();
        let cp = up.sub(CANARY_SIZE);
        let dp = (cp as usize & !page_mask) as *mut u8;
        let bp = dp.sub(page_size * 2);
        (up, cp, dp, bp)
    };

    // Metadata page is PROT_READ; reading unprotected_size is valid.
    let unprotected_size = unsafe { ptr::read_unaligned(base_ptr.cast::<usize>()) };
    let total_size = page_size * 2 + unprotected_size + page_size;

    // Validate canary via xor-accumulate.
    // Timing is irrelevant: the canary guards against heap corruption
    // (abort-or-continue), not against a timing side-channel on secret
    // comparison.
    let stored = unsafe { std::slice::from_raw_parts(canary_ptr, CANARY_SIZE) };
    let diff = stored
        .iter()
        .zip(s.canary.iter())
        .fold(0u8, |acc, (&a, &b)| acc | (a ^ b));
    if diff != 0 {
        abort();
    }

    unsafe {
        // Make all pages writable before zeroing.
        let _ = mprotect(
            NonNull::new_unchecked(base_ptr.cast()),
            total_size,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        );

        // Zero the entire data page (canary + key + padding) with volatile writes.
        let data_slice = std::slice::from_raw_parts_mut(unprotected_ptr, unprotected_size);
        data_slice.zeroize();

        // Unlock from RAM.
        let _ = munlock(
            NonNull::new_unchecked(unprotected_ptr.cast()),
            unprotected_size,
        );
    }

    // Linux: restore dump and fork visibility before freeing.
    #[cfg(target_os = "linux")]
    unsafe {
        let _ = madvise(
            NonNull::new_unchecked(unprotected_ptr.cast()),
            unprotected_size,
            MmapAdvise::MADV_DODUMP,
        );
        let _ = madvise(
            NonNull::new_unchecked(unprotected_ptr.cast()),
            unprotected_size,
            MmapAdvise::MADV_DOFORK,
        );
    }

    // SAFETY: same layout and alignment as locked_alloc.
    unsafe {
        let layout = Layout::from_size_align_unchecked(total_size, page_size);
        dealloc(base_ptr, layout);
    }

    // Suppress unused variable warning when not on Linux.
    let _ = user_ptr;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locked_key_alloc_zeroed() {
        let key = LockedKey::alloc().expect("alloc failed");
        assert_eq!(key.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_locked_key_write_read() {
        let mut key = LockedKey::alloc().expect("alloc failed");
        key.as_mut().copy_from_slice(&[0xABu8; 32]);
        assert_eq!(key.as_bytes(), &[0xABu8; 32]);
    }

    #[test]
    fn test_locked_key_from_raw() {
        let bytes = [0x42u8; 32];
        let key = LockedKey::from_raw(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }
}
