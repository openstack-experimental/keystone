# METADATA
# description: Policy for checking user membership in a group
package identity.group.user.check

import data.identity

# Checking user membership in a group.
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
	"reader" in input.credentials.roles
	identity.membership_domains_match_domain_scope
}

violation contains {"field": "domain_id", "msg": "checking user membership in a group in a domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"reader" in input.credentials.roles
	not identity.membership_domains_match_domain_scope
}

violation contains {"field": "domain_id", "msg": "checking user membership in a group requires a reader role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "reader" in input.credentials.roles
}
