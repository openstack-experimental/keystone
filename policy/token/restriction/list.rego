# METADATA
# description: Policy for listing token restrictions
package identity.token_restriction.list

import data.identity

# List token restriction.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"manager" in input.credentials.roles
}

allow if {
	"member" in input.credentials.roles
	identity.own_token_restriction
}

violation contains {"field": "domain_id", "msg": "showing token restrictions requires `admin` role."} if {
	identity.foreign_token_restriction
	not "admin" in input.credentials.roles
}
