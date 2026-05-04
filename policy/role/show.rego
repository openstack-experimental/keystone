# METADATA
# title: Show role
# description: Policy for fetching a single role
package identity.role.show

import data.identity

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
