# METADATA
# description: Policy for updating token restrictions
package identity.token.token_restriction.update

import data.identity.token

# Update token restriction.
#
# The `input.target.restriction` is the update patch (TokenRestrictionUpdate):
#   allow_renew:    bool (optional)  Allow token renew.
#   allow_rescope:  bool (optional)  Allow token rescope.
#   project_id:     string (optional) Project ID that the token must be bound to.
#   user_id:        string (optional) User ID that the token must be bound to.
#   roles:          array (optional)  Bound token roles.
#
# The `input.existing.restriction` is the stored restriction object (TokenRestriction):
#   allow_renew:    bool            Allow token renew.
#   allow_rescope:  bool            Allow token rescope.
#   domain_id:      string          Domain ID the token restriction belongs to.
#   id:             string          Token restriction ID.
#   project_id:     string (optional) Project ID that the token must be bound to.
#   user_id:        string (optional) User ID that the token must be bound to.
#   roles:          array            Bound token roles.
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

violation contains {"field": "domain_id", "msg": "updating token restrictions in other domain requires `admin` role."} if {
	token.foreign_token_restriction
	not "admin" in input.credentials.roles
}
