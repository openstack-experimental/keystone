# METADATA
# title: Create credential
# description: Policy for creating a credential
package identity.credential.create

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
}

# METADATA
# description: "Explicitly targeting one's own user is equivalent to omitting it."
allow if {
	"member" in input.credentials.roles
	input.target.credential.user_id == input.credentials.user_id
}
