# METADATA
# description: Policy for revoking roles from users on system
package identity.system.user.role.revoke

import data.identity

# Revoke user a role on the system scope.

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

violation contains {"field": "system", "msg": "revoking a role from a user on the system requires admin role."} if {
	not "admin" in input.credentials.roles
}

violation contains {"field": "system", "msg": "revoking a role from a user on the system requires system scope for manager role."} if {
	"manager" in input.credentials.roles
	input.credentials.system != "all"
}
