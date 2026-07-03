# METADATA
# title: Create credential
# description: Policy for creating a credential
package identity.credential.create

import data.identity.credential as credential_common

# Create credential.
#
# The `input.target.credential` is the new credential object (CredentialCreate):
#   blob:        string            The decrypted secret blob, as a JSON string.
#   type:        string            Credential type.
#   project_id:  string (optional) Project the credential is bound to.
#   user_id:     string (optional) The owning user ID; a null value means the
#                                  caller's own user (defaulted server-side
#                                  under user scope).
#
# The `input.existing` is null
#
# Delegation boundary (OSSA-2026-015): a delegated caller (trust,
# application credential) may only create a credential bound to its own
# delegation project — never an unscoped credential (e.g. TOTP/MFA) and
# never one bound to a different project — otherwise a stolen delegation
# token could plant a credential the delegator never intended to expose
# outside the delegated project. The boundary is anchored on the
# chain-derived `input.credentials.delegated_project_id` (the delegation's
# own immutable project), not the token scope, with the scope pinned equal
# as a drift tripwire.
#
# Restricted application credentials and EC2 (OSSA-2026-005 /
# CVE-2026-33551): a *restricted* application credential must not be usable
# to mint an `ec2`-type credential at all — once used via `/v3/ec2tokens`,
# an EC2 credential authenticates independently of its creator's own role
# restriction, so allowing this would let a reader-only restricted app-cred
# obtain a credential carrying the parent user's full permissions.
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

# METADATA
# description: "Omitting `user_id` targets the caller's own user (server-side default)."
allow if {
	"member" in input.credentials.roles
	not input.target.credential.user_id
	credential_common.not_delegated_or_bound_to_own_project(object.get(input.target.credential, "project_id", null))
	not is_restricted_app_cred_creating_ec2
}

# METADATA
# description: "Explicitly targeting one's own user is equivalent to omitting it."
allow if {
	"member" in input.credentials.roles
	input.target.credential.user_id == input.credentials.user_id
	credential_common.not_delegated_or_bound_to_own_project(object.get(input.target.credential, "project_id", null))
	not is_restricted_app_cred_creating_ec2
}

# METADATA
# description: "A restricted application credential may never create an ec2-type credential."
is_restricted_app_cred_creating_ec2 if {
	input.credentials.auth_type == "application_credential"
	not input.credentials.unrestricted
	input.target.credential.type == "ec2"
}
