# METADATA
# description: Policy for finishing passkey registration
package identity.user.passkey.register.finish

import data.identity

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
