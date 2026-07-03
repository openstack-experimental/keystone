# METADATA
# title: Update credential
# description: Policy for updating a credential
package identity.credential.update

import data.identity.credential as credential_common

# Update credential.
#
# The `input.target.credential` is the update patch (CredentialUpdate):
#   blob:        string (optional)  New decrypted secret blob, as a JSON string.
#   project_id:  string (optional)  New project association.
#   type:        string (optional)  New credential type.
#
# The `input.existing.credential` is the stored credential object (Credential),
# see `identity/credential/show`.
#
# Delegation boundary (OSSA-2026-015): see `identity/credential/show` — a
# delegated caller (trust, application credential) may only update
# credentials already bound to its own delegation project (anchored on the
# chain-derived `input.credentials.delegated_project_id`, not the token
# scope), and may not use `project_id` in the patch to move a credential out
# of that project; unscoped credentials (e.g. TOTP/MFA) are out-of-scope for
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
# description: "A non-delegated caller may update their own credential."
allow if {
	"member" in input.credentials.roles
	not input.credentials.is_delegated
	input.existing.credential.user_id == input.credentials.user_id
}

# METADATA
# description: "A delegated caller may update their own credential only when it stays bound to the delegation's own project."
allow if {
	"member" in input.credentials.roles
	input.credentials.is_delegated
	input.existing.credential.user_id == input.credentials.user_id
	credential_common.bound_to_own_delegation_project(input.existing.credential.project_id)
	not moves_project_out_of_scope
}

# METADATA
# description: "True when the patch sets project_id to something other than the delegation's own project."
moves_project_out_of_scope if {
	input.target.credential.project_id
	input.target.credential.project_id != input.credentials.delegated_project_id
}
