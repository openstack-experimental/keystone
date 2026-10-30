# METADATA
# description: Policy for checking user roles on a domain
package identity.domain.user.role.check

import data.identity.assignment

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

allow if {
	"reader" in input.credentials.roles
	assignment.domain_user_role_domain_matches
}

violation contains {"field": "domain_id", "msg": "checking domain-user-role assignment requires domain scope matching the domain of all targets."} if {
	not assignment.domain_user_role_domain_matches
}
