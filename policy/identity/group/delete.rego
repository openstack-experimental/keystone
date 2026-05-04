# METADATA
# description: Policy for deleting identity groups
package identity.group.delete

import data.identity

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "removing a user group in domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "removing a user group requires a manager role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}
