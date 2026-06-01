# METADATA
# description: Policy for showing project details
package identity.resource.project.show

import data.identity

# Show a project.
#
# The `input.target` is null.
# The `input.existing.project` is the stored resource object (Project):
#   description:  string (optional)  The project description.
#   domain_id:    string            The ID of the domain for the project.
#   enabled:      bool              Whether the project is enabled.
#   id:           string            The project ID.
#   name:         string            The project name.
#   is_domain:    bool              Whether the project also acts as a domain.
#   parent_id:    string (optional)  The ID of the parent project.
#
default allow := false

allow if {
	input.credentials.is_admin
}

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

allow if {
	"reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "showing a project in a domain different from the domain scope requires system admin."} if {
	not input.credentials.is_admin
	"reader" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "showing a project requires system admin or `reader` role with system scope or domain scope."} if {
	not input.credentials.is_admin
	not "reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}
