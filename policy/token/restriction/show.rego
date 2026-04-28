# METADATA
# description: Policy for viewing token restriction details
package identity.token_restriction.show

import data.identity

# Show single token restriction.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_token_restriction
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "showing token restrictions requires `admin` role."} if {
	identity.foreign_token_restriction
	not "admin" in input.credentials.roles
}
