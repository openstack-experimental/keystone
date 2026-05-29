# METADATA
# description: Policy for creating token restrictions
package identity.token.token_restriction.create

import data.identity.token

# Create token restriction.
#
# The `input.target.restriction` is the new restriction object (TokenRestrictionCreate):
#   allow_renew:    bool            Allow token renew.
#   allow_rescope:  bool            Allow token rescope.
#   domain_id:      string          Domain ID the token restriction belongs to.
#   project_id:     string (optional) Project ID that the token must be bound to.
#   user_id:        string (optional) User ID that the token must be bound to.
#   roles:          array            Bound token roles.
#
# The `input.existing` is null
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
	input.target.restriction.user_id != null
	input.credentials.user_id == input.target.restriction.user_id
}

violation contains {"field": "domain_id", "msg": "creating token restrictions in other domain requires `admin` role."} if {
	token.foreign_token_restriction
	not "admin" in input.credentials.roles
}
