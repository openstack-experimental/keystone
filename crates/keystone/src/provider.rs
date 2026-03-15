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
//! # Provider manager
//!
//! Provider manager provides access to the individual service providers. This
//! gives an easy interact for passing overall manager down to the individual
//! providers that might need to call other providers while also allowing an
//! easy injection of mocked providers.
pub use openstack_keystone_core::provider::*;
