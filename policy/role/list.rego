# METADATA
# title: List roles
# description: Policy for listing roles
package identity.role.list

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
	identity.domain_matches_domain_scope
}
