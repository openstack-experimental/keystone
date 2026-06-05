# METADATA
# description: Policy for granting roles to users on system
package identity.system.user.role.grant

import data.identity

# Grant user a role on the system scope.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	"manager" in input.credentials.roles
	input.credentials.system == "all"
}

violation contains {"field": "system", "msg": "granting a role to a user on the system requires admin role."} if {
	not "admin" in input.credentials.roles
}

violation contains {"field": "system", "msg": "granting a role to a user on the system requires system scope for manager role."} if {
	"manager" in input.credentials.roles
	input.credentials.system != "all"
}

