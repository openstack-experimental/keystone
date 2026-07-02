# METADATA
# title: Update credential
# description: Policy for updating a credential
package identity.credential.update

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
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

# METADATA
# description: "The credential owner may update their own credential."
allow if {
	"member" in input.credentials.roles
	input.existing.credential.user_id == input.credentials.user_id
}
