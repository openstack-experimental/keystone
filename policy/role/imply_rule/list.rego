# METADATA
# title: List role imply rules
# description: Policy for listing role imply rules
package identity.role.imply_rule.list

import data.identity

# List role imply rules.
#
# The `input.target` is null (no filters)
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

# METADATA
# description: "`reader` role with system scope is allowed"
allow if {
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

violation contains {"field": "", "msg": "listing role imply rules requires `admin` role or `reader` role with system scope."} if {
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
}