# METADATA
# description: Policy for checking group roles on a project
package identity.project.group.role.check

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
	assignment.project_group_role_domain_matches
}

violation contains {"field": "domain_id", "msg": "checking project-group-role assignment requires domain scope matching the domain of all targets."} if {
	not assignment.project_group_role_domain_matches
}
