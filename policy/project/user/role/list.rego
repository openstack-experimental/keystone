package identity.project.user.role.list

import data.identity
import data.identity.assignment

# List roles granted to a user on a project

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"reader" in input.credentials.roles
	input.credentials.scope == "system"
}

allow if {
	"reader" in input.credentials.roles
	assignment.project_user_role_domain_matches
}

violation contains {"field": "role", "msg": "listing user roles on a project requires admin or reader role."} if {
	not "admin" in input.credentials.roles
	not "reader" in input.credentials.roles
}

violation contains {"field": "scope", "msg": "reader role requires system scope or domain scope matching the user and project domain."} if {
	"reader" in input.credentials.roles
	input.credentials.scope != "system"
	not assignment.project_user_role_domain_matches
}
