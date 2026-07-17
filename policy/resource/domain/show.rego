# METADATA
# description: Policy for showing domain details
package identity.resource.domain.show

import data.identity

# Show a domain.
#
# The `input.target` is null.
# The `input.existing.domain` is the stored resource object (Domain):
#   description: string (optional)  The domain description.
#   enabled:     bool               Whether the domain is enabled.
#   id:          string             The domain ID.
#   name:        string             The domain name.
#
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
	"manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}

# METADATA
# description: A project-scoped caller can view the domain their project belongs to
allow if {
	input.credentials.project_domain_id == input.existing.domain.id
}

violation contains {"field": "id", "msg": "showing a domain requires system admin, `reader` role with system scope, `manager` role with matching domain scope, or a project scoped to the domain."} if {
	not input.credentials.is_admin
}
