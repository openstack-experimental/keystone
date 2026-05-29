# METADATA
# description: Policy for viewing token restriction details
package identity.token.token_restriction.show

import data.identity.token

# Show single token restriction.
#
# The `input.target.restriction` is the stored restriction object (TokenRestriction):
#   allow_renew:    bool            Allow token renew.
#   allow_rescope:  bool            Allow token rescope.
#   domain_id:      string          Domain ID the token restriction belongs to.
#   id:             string          Token restriction ID.
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
	token.own_token_restriction
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "showing token restrictions requires `admin` role."} if {
	token.foreign_token_restriction
	not "admin" in input.credentials.roles
}
