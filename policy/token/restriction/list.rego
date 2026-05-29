# METADATA
# description: Policy for listing token restrictions
package identity.token.token_restriction.list

import data.identity.token

# List token restrictions.
#
# The `input.target.restriction` contains query parameters (TokenRestrictionListParameters):
#   domain_id:    string (optional)  Domain id.
#   user_id:      string (optional)  User id.
#   project_id:   string (optional)  Project id.
#
# The `input.existing` is null
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"manager" in input.credentials.roles
}

allow if {
	"member" in input.credentials.roles
	token.own_token_restriction
}

violation contains {"field": "domain_id", "msg": "showing token restrictions requires `admin` role."} if {
	token.foreign_token_restriction
	not "admin" in input.credentials.roles
}
