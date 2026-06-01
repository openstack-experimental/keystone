# METADATA
# description: Policy for listing projects
package identity.resource.project.list

import data.identity

# List projects.
#
# The `input.target.project` contains query parameters (ProjectListParameters):
#   domain_id: string (optional)  Filter projects by domain ID.
#   ids:       string (optional)  Filter projects by ID.
#   name:      string (optional)  Filter projects by name.
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
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

allow if {
	"reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "listing projects requires system admin or `reader` role with system scope or domain scope."} if {
	not input.credentials.is_admin
	not "reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}
