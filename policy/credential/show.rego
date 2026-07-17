# METADATA
# title: Show credential
# description: Policy for fetching a single credential
package identity.credential.show

import data.identity.credential as credential_common

# Show credential.
#
# The `input.existing.credential` is the stored credential object (Credential):
#   id:          string            Credential ID.
#   blob:        string            The decrypted secret blob, as a JSON string.
#   project_id:  string (optional) Project the credential is bound to.
#   type:        string            Credential type.
#   user_id:     string            The owning user ID.
#
# The `input.target` is null
#
# This is also invoked by `identity/credential/list`'s per-item
# re-enforcement pass (ADR 0019 §2, CVE-2019-19687).
#
# Delegation boundary (OSSA-2026-015): a trust- or application-credential-
# scoped caller (`input.credentials.is_delegated`) may only reach a
# credential bound to the *same* project the delegation itself is bound to.
# The boundary is anchored on `input.credentials.delegated_project_id` — the
# delegation's own immutable project taken from the authentication chain —
# rather than on `input.credentials.project_id` (the token scope), so a
# scope rebind cannot move the boundary. The two are pinned equal at
# token-issuance time, so `delegated == scope` is additionally asserted as a
# scope-drift tripwire. Credentials with no project binding (e.g. TOTP/MFA
# seeds) are out-of-scope for any delegated caller, since stealing a
# delegation token must never be enough to exfiltrate or destroy a user's
# MFA binding.
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

# METADATA
# description: "A non-delegated caller (password, plain token, TOTP, ...) may always read their own credential."
allow if {
	not input.credentials.is_delegated
	input.existing.credential.user_id == input.credentials.user_id
}

# METADATA
# description: "A delegated caller (trust, application credential) may read their own credential only when it is bound to the delegation's own project."
allow if {
	input.credentials.is_delegated
	input.existing.credential.user_id == input.credentials.user_id
	credential_common.bound_to_own_delegation_project(object.get(input.existing.credential, "project_id", null))
}
