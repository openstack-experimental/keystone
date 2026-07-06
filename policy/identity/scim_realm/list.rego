# METADATA
# description: Policy for listing SCIM realms (ADR 0024 §2.A)
package identity.scim_realm.list

import data.identity

# List SCIM realms.
#
# The `input.target.scim_realm` contains query parameters:
#   domain_id: string            Domain to list realms for.
#   enabled:   bool (optional)   Filter by enabled/disabled state.
#
# The `input.existing` is null
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	"manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "listing SCIM realms in a domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "listing SCIM realms requires a manager role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}
