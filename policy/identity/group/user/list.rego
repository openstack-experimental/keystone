# METADATA
# description: Policy for listing users of a group
package identity.group.user.list

import data.identity

# Listing users of a group.
#
# The `input.existing.group` is the stored group object and
# `input.existing.user` is the stored user object (`null` when the object does
# not exist, which only `admin` is allowed to pass to receive the 404).
#   domain_id:    string            Group domain ID.
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "listing users of a group in a domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"reader" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "listing users of a group requires a reader role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "reader" in input.credentials.roles
}
