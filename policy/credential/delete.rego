# METADATA
# title: Delete credential
# description: Policy for deleting a credential
package identity.credential.delete

import data.identity.credential as credential_common

# Delete credential.
#
# The `input.existing.credential` is the stored credential object (Credential),
# see `identity/credential/show`.
#
# The `input.target` is null
#
# Delegation boundary (OSSA-2026-015): see `identity/credential/show` — a
# delegated caller (trust, application credential) may only delete
# credentials bound to its own delegation project, anchored on the
# chain-derived `input.credentials.delegated_project_id` (not the token
# scope); unscoped credentials (e.g. TOTP/MFA) are out-of-scope for
# delegated callers entirely.
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

# METADATA
# description: "A non-delegated caller may delete their own credential."
allow if {
	"member" in input.credentials.roles
	not input.credentials.is_delegated
	input.existing.credential.user_id == input.credentials.user_id
}

# METADATA
# description: "A delegated caller may delete their own credential only when it is bound to the delegation's own project."
allow if {
	"member" in input.credentials.roles
	input.credentials.is_delegated
	input.existing.credential.user_id == input.credentials.user_id
	credential_common.bound_to_own_delegation_project(input.existing.credential.project_id)
}
