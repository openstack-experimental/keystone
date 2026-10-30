# METADATA
# description: Policy for revoking roles from groups on a domain
package identity.domain.group.role.revoke

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
	assignment.domain_group_role_domain_matches
	identity.domain_managed_target_role
}

violation contains {"field": "domain_id", "msg": "revoking a role from a group on a domain requires admin or manager role in the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
}

violation contains {"field": "role", "msg": "revoking a role from a group on a domain as a manager is limited to the manager, member and reader roles."} if {
	not "admin" in input.credentials.roles
	not identity.domain_managed_target_role
}

violation contains {"field": "domain_id", "msg": "revoking a role from a group on a domain requires domain scope matching the domain_id of the target domain, group and role (or a global role)."} if {
	not assignment.domain_group_role_domain_matches
}
