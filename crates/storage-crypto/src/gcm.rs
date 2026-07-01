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
//! Shared AES-256-GCM array type aliases used by [`crate::kek`] and
//! [`crate::cipher`].
//!
//! Kept in one place so the two call sites can't drift apart on the GCM
//! parameter sizes (key = 32B, nonce = 12B, tag = 16B).

use hybrid_array::Array;
use typenum::{U12, U16, U32};

pub(crate) type GcmKey = Array<u8, U32>;
pub(crate) type GcmNonce = Array<u8, U12>;
pub(crate) type GcmTag = Array<u8, U16>;
