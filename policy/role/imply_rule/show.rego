# METADATA
# title: Show role imply rule
# description: Policy for fetching a single role imply rule
package identity.role.imply_rule.show

import data.identity

# Show role imply rule.
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

# METADATA
# description: "`reader` role with system scope is allowed"
allow if {
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

violation contains {"field": "", "msg": "showing a role imply rule requires `admin` role or `reader` role with system scope."} if {
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
}