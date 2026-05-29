# METADATA
# description: Policy for finishing passkey registration
package identity.user.passkey.register.finish

import data.identity

# Finish registering a passkey for the user
#
# The `input.target.user` is the user object (User):
#   domain_id:    string        domain ID
#
# The `input.target.id` is the user ID:
#   id:           string        user ID
#
# The `input.existing` is null
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"manager" in input.credentials.roles
	input.credentials.domain_id == input.target.user.domain_id
}

allow if {
	input.credentials.user_id == input.target.id
}
