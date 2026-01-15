package identity.project.create

import data.identity

# Create a new project

default allow := false

allow if {
	"admin" in input.credentials.roles
}

project_domain_matches_domain_scope if {
	input.target.project.domain_id != null
	input.target.project.domain_id = input.credentials.domain_id
}

allow if {
	"manager" in input.credentials.roles
	project_domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "creating a new project requires a manager role in the domain scope for the domain where the project is being created."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	not project_domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "creating a new project requires a manager role in the domain scope for the domain where the project is being created."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	project_domain_matches_domain_scope
}
