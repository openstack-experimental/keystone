# METADATA
# description: Policy for updating identity groups
package identity.group.update

import data.identity

# Update an existing user group
#
# The `input.target.group` is the update patch (GroupUpdate):
#   name:         string (optional)  Group name.
#   description:  string (optional)  Group description.
#
# The `input.existing.group` is the stored group object:
#   domain_id:    string            Group domain ID.
#   description:  string (optional)  Group description.
#   id:           string            Group ID.
#   name:         string            Group name.
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "updating a user group in domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "updating a user group requires a manager role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}
