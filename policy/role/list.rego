# METADATA
# title: List roles
# description: Policy for listing roles
package identity.role.list

import data.identity

# List roles.
#
# The `input.target.role` contains query parameters:
#   domain_id:    string|null   domain ID for filtering
#
# The `input.existing` is null
#
default allow := false

# METADATA
# description: "`Admin` is allowed by default"
allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

# METADATA
# description: "`Manager` is allowed for global roles and roles belonging to the scope domain."
allow if {
	"manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}
