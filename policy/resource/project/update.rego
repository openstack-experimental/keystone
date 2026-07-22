# METADATA
# description: Policy for updating projects
package identity.resource.project.update

import data.identity

# Update a project.
#
# The `input.target.project` is the update patch (ProjectUpdate):
#   description: string (optional)  The project description.
#   enabled:     bool (optional)    Whether the project is enabled.
#   name:        string (optional)  The project name.
#
# The `input.existing.project` is the stored resource object (Project):
#   description: string (optional)  The project description.
#   domain_id:   string             The ID of the domain for the project.
#   enabled:     bool               Whether the project is enabled.
#   id:          string             The project ID.
#   name:        string             The project name.
#   is_domain:   bool               Whether the project also acts as a domain.
#   parent_id:   string (optional)  The ID of the parent project.
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

violation contains {"field": "domain_id", "msg": "updating a project requires system admin or `manager` role in the domain scope."} if {
	not input.credentials.is_admin
	not "manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}
