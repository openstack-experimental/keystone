# METADATA
# description: Policy for creating projects
package identity.project.create

import data.identity

# Create a new project
#
# The `input.target.project` is the new project object (ProjectCreate):
#   description:  string (optional)  The description of the project.
#   domain_id:    string            The ID of the domain for the project.
#   enabled:      bool              If set to true, project is enabled.
#   is_domain:    bool              Indicates whether the project also acts as a domain.
#   name:         string            The name of the project.
#   parent_id:    string (optional)  The ID of the parent of the project.
#
# The `input.existing` is null
#
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
