# METADATA
# title: Delete credential
# description: Policy for deleting a credential
package identity.credential.delete

# Delete credential.
#
# The `input.existing.credential` is the stored credential object (Credential),
# see `identity/credential/show`.
#
# The `input.target` is null
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

# METADATA
# description: "The credential owner may delete their own credential."
allow if {
	"member" in input.credentials.roles
	input.existing.credential.user_id == input.credentials.user_id
}
