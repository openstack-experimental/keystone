# METADATA
# title: Show role
# description: Policy for fetching a single role
package identity.role.show

import data.identity

# Show role.
#
# The `input.target.role` is the stored role object (Role):
#   description:  string (optional)  Role description.
#   domain_id:    string (optional)  Role domain ID.
#   id:           string            Role ID.
#   name:         string            Role name.
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
	identity.own_role_or_global_role
}
