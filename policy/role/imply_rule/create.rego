# METADATA
# title: Create role imply rule
# description: Policy for creating a role imply rule
package identity.role.imply_rule.create

import data.identity

# Create role imply rule.
#
# The `input.target.role_imply_rule` is the new rule object (RoleImply):
#   prior_role:       RoleRef    The prior role reference (id, name, domain_id).
#   implied_role:     RoleRef    The implied role reference (id, name, domain_id).
#
# The `input.existing` is null
#
default allow := false

# METADATA
# description: "`Admin` role is allowed"
allow if {
	"admin" in input.credentials.roles
}

# METADATA
# description: "System admin is allowed"
allow if {
	input.credentials.is_admin
}

violation contains {"field": "", "msg": "creating a role imply rule requires `admin` role."} if {
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
}
