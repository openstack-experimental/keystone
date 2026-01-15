package identity.project.user.role.check

import data.identity
import data.identity.assignment

# Check whether the user has a role assigned on the project.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

allow if {
	"reader" in input.credentials.roles
	assignment.project_user_role_domain_matches
}

violation contains {"field": "domain_id", "msg": "checking project-user-role assignment requires domain scope matching the domain of all targets."} if {
	not assignment.project_user_role_domain_matches
}
