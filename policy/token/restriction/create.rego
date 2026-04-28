# METADATA
# description: Policy for creating token restrictions
package identity.token_restriction.create

import data.identity

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"manager" in input.credentials.roles
	identity.own_token_restriction
}

allow if {
	"member" in input.credentials.roles
	input.target.user_id != null
	input.credentials.user_id == input.target.user_id
}

violation contains {"field": "domain_id", "msg": "creating token restrictions in other domain requires `admin` role."} if {
	identity.foreign_token_restriction
	not "admin" in input.credentials.roles
}
