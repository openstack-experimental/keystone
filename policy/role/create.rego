# METADATA
# title: Create role
# description: Policy for creating role
package identity.role.create

import data.identity

default allow := false

# METADATA
# description: "`Admin` is allowed by default"
allow if {
	"admin" in input.credentials.roles
}
