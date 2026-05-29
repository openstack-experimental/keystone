# METADATA
# title: Create role
# description: Policy for creating role
package identity.role.create

import data.identity

# Create role.
#
# The `input.target.role` is the new role object (RoleCreate):
#   description:  string (optional)  The role description.
#   domain_id:    string (optional)  The domain ID of the role.
#   name:         string            The role name.
#
# The `input.existing` is null
#
default allow := false

# METADATA
# description: "`Admin` is allowed by default"
allow if {
	"admin" in input.credentials.roles
}
