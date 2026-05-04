# METADATA
# description: Policy for listing users
package identity.user.list

import data.identity

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "listing users in domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "listing users requires a reader role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}
