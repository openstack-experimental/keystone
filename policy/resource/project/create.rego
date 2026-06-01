# METADATA
# description: Policy for creating projects
package identity.resource.project.create

import data.identity

# Create a new project
#
# The `input.target.project` is the new project object (ProjectCreate):
#   description:  string (optional)  The description of the project.
#   domain_id:    string            The ID of the domain for the project.
#   enabled:      bool              Whether the project is enabled.
#   is_domain:    bool              Whether the project also acts as a domain.
#   name:         string            The project name.
#   parent_id:    string (optional)  The ID of the parent of the project.
#
# The `input.existing` is null
#
default allow := false

allow if {
	input.credentials.is_admin
}

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "creating a project requires system admin or `manager` role in the domain scope."} if {
	not input.credentials.is_admin
	not "manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}
