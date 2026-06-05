# METADATA
# title: Delete role
# description: Policy for deleting a role
package identity.role.delete

import data.identity

# Show role.
#
# The `input.existing.role` is the stored role object (Role):
#   description:  string (optional)  Role description.
#   domain_id:    string (optional)  Role domain ID.
#   id:           string            Role ID.
#   name:         string            Role name.
#
# The `input.target` is null
#
default allow := false

# METADATA
# description: "`Admin` is allowed by default"
allow if {
	"admin" in input.credentials.roles
}

# METADATA
# description: "`Manager` is allowed for global roles and roles belonging to the scope domain."
allow if {
	"manager" in input.credentials.roles
	identity.own_role_or_global_role
}
