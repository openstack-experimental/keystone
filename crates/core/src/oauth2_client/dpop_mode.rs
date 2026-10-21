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
//! # Effective DPoP enforcement mode (ADR 0043 §1)

use openstack_keystone_config::DpopMode;

/// The effective DPoP mode of a request: the strictest of the global, domain
/// and client levels (`disabled < optional < required`).
///
/// `dpop_bound_access_tokens` on the client means `required` for that client.
/// The global value is a floor: a lower domain value never weakens it.
pub fn effective_dpop_mode(
    global: DpopMode,
    domain: DpopMode,
    client_bound_access_tokens: bool,
) -> DpopMode {
    let client = if client_bound_access_tokens {
        DpopMode::Required
    } else {
        DpopMode::Disabled
    };
    global.max(domain).max(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use DpopMode::*;

    #[test]
    fn test_strictest_level_wins() {
        let modes = [Disabled, Optional, Required];
        for global in modes {
            for domain in modes {
                for bound in [false, true] {
                    let expected = if bound { Required } else { global.max(domain) };
                    assert_eq!(
                        effective_dpop_mode(global, domain, bound),
                        expected,
                        "global={global} domain={domain} bound={bound}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_global_is_a_floor() {
        assert_eq!(effective_dpop_mode(Required, Disabled, false), Required);
        assert_eq!(effective_dpop_mode(Optional, Disabled, false), Optional);
    }

    #[test]
    fn test_domain_raises_global_optional() {
        assert_eq!(effective_dpop_mode(Optional, Required, false), Required);
    }

    #[test]
    fn test_client_flag_requires_dpop() {
        assert_eq!(effective_dpop_mode(Disabled, Disabled, true), Required);
    }
}
