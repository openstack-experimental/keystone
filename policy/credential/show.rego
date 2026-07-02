# METADATA
# title: Show credential
# description: Policy for fetching a single credential
package identity.credential.show

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
# description: "The credential owner may always read their own credential."
allow if {
	input.existing.credential.user_id == input.credentials.user_id
}
