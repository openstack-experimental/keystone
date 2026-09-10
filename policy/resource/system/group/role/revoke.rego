# METADATA
# description: Policy for revoking roles from groups on system
package identity.system.group.role.revoke

import data.identity

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

violation contains {"field": "system", "msg": "revoking a role from a group on the system requires admin role."} if {
        not "admin" in input.credentials.roles
}

violation contains {"field": "system", "msg": "revoking a role from a group on the system requires system scope for manager role."} if {
        "manager" in input.credentials.roles
        input.credentials.system != "all"
}