# METADATA
# description: Policy for removing a user from a group
package identity.group.user.remove

import data.identity

# Removing a user from a group.
#
# The `input.existing.group` is the stored group object and
# `input.existing.user` is the stored user object (`null` when the object does
# not exist, which only `admin` is allowed to pass to receive the 404).
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"manager" in input.credentials.roles
	identity.membership_domains_match_domain_scope
}

violation contains {"field": "domain_id", "msg": "removing a user from a group in a domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	not identity.membership_domains_match_domain_scope
}

violation contains {"field": "domain_id", "msg": "removing a user from a group requires a manager role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
}
