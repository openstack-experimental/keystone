# METADATA
# description: Policy for deleting token restrictions
package identity.token.token_restriction.delete

import data.identity.token

# Delete token restriction.
#
# The `input.existing.restriction` is the stored restriction object:
#   domain_id:    string        domain ID
#   user_id:      string|null   user ID
#   role_ids:     [string]      list of role IDs
#
# The `input.target` is null
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"manager" in input.credentials.roles
	token.own_token_restriction
}

allow if {
	"member" in input.credentials.roles
	input.existing.restriction.user_id != null
	input.credentials.user_id == input.existing.restriction.user_id
}

violation contains {"field": "domain_id", "msg": "deleting token restrictions in other domain requires `admin` role."} if {
	token.foreign_token_restriction
	not "admin" in input.credentials.roles
}
