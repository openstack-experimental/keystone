package identity.project.user.role.check

import data.identity

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
	input.target.project.domain_id != null
	input.target.user.domain_id != null
	input.credentials.domain_id == input.target.user.domain_id
	input.credentials.domain_id == input.target.project.domain_id
	identity.own_role_or_global_role
}

# violation contains {"field": "domain_id", "msg": "checking project-user-role assignment requires domain scope."} if {
# 	not "admin" in input.credentials.roles
# }
