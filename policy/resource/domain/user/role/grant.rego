# METADATA
# description: Policy for granting roles to users on a domain
package identity.domain.user.role.grant

import data.identity
import data.identity.assignment

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	"manager" in input.credentials.roles
	assignment.domain_user_role_domain_matches
	identity.domain_managed_target_role
}

violation contains {"field": "domain_id", "msg": "granting a role to a user on a domain requires admin or manager role in the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
}

violation contains {"field": "role", "msg": "granting a role to a user on a domain as a manager is limited to the manager, member and reader roles."} if {
	not "admin" in input.credentials.roles
	not identity.domain_managed_target_role
}

violation contains {"field": "domain_id", "msg": "granting a role to a user on a domain requires domain scope matching the domain_id of the target domain, user and role (or a global role)."} if {
	not assignment.domain_user_role_domain_matches
}
