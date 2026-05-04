# METADATA
# description: Policy for viewing identity group details
package identity.group.show

import data.identity

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "reading a user group in domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "reading a user group requires a reader role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}
