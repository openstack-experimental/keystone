package identity.project.user.role.grant

import data.identity
import data.identity.assignment

# Grant user a role on a project

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"manager" in input.credentials.roles
	assignment.project_role_domain_matches
}

violation contains {"field": "domain_id", "msg": "granting a role to a user on a project requires admin or manager role in the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "granting a role to a user on a project requires domain scope matching the domain_id of the target project and role (or a global role)."} if {
	assignment.project_role_domain_matches
}
