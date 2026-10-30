# METADATA
# description: Policy for listing roles of a group on a project
package identity.project.group.role.list

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
	assignment.project_group_domain_matches
}

violation contains {"field": "domain_id", "msg": "listing project-group-role assignment requires domain scope matching the domain of all targets."} if {
	not assignment.project_group_domain_matches
}
