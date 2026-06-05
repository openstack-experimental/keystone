# METADATA
# title: Delete role imply rule
# description: Policy for deleting a role imply rule
package identity.role.imply_rule.delete

import data.identity

# Delete role imply rule.
#
# The `input.target` is null
#
# The `input.existing.role_imply_rule` is the stored rule object (RoleImply):
#   prior_role:       RoleRef    The prior role reference (id, name, domain_id).
#   implied_role:     RoleRef    The implied role reference (id, name, domain_id).
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

violation contains {"field": "", "msg": "deleting a role imply rule requires `admin` role."} if {
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
}