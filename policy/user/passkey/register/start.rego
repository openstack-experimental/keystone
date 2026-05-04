# METADATA
# description: Policy for starting passkey registration
package identity.user.passkey.register.start

import data.identity

# Start registering a passkey for the user

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"manager" in input.credentials.roles
	input.credentials.domain_id == input.target.domain_id
}

allow if {
	input.credentials.user_id == input.target.id
}
