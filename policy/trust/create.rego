# METADATA
# title: Create trust
# description: Policy for creating a trust
package identity.trust.create

import data.identity.trust as trust_common

# Create trust.
#
# The `input.target.trust` is the new trust object (TrustCreate):
#   trustor_user_id: string            Must equal the caller's own user_id;
#                                      a trust is always self-issued by its
#                                      trustor.
#   trustee_user_id: string            The user the authorization is
#                                      delegated to.
#   project_id:      string (optional) Project being delegated on.
#   roles:           array             Roles being delegated.
#
# The `input.existing` is null
#
# Delegation boundary (OSSA-2026-015): a delegated caller (trust,
# application credential) may only create a new trust bound to its own
# delegation project -- never an unscoped trust and never one bound to a
# different project -- anchored on the chain-derived
# `input.credentials.delegated_project_id`, not the token scope, with the
# scope pinned equal as a drift tripwire.
#
default allow := false

# METADATA
# description: >
#   A trust is always self-issued: the caller must be its own trustor.
#   Matches python keystone's `identity:create_trust` policy
#   ("user_id:%(target.trust.trustor_user_id)s"), which has no admin bypass
#   -- even an admin cannot create a trust on behalf of another user -- and
#   no role requirement either: whether the trustor actually holds the
#   roles being delegated is checked provider-side
#   (`TrustService::create_trust`), not here.
allow if {
	trust_common.is_trustor(input.target.trust)
	trust_common.not_delegated_or_bound_to_own_project(object.get(input.target.trust, "project_id", null))
}
