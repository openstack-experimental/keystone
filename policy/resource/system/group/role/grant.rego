# METADATA
# description: Policy for granting roles to groups on system
package identity.system.group.role.grant

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

violation contains {"field": "system", "msg": "granting a role to a group on the system requires admin role."} if {
        not "admin" in input.credentials.roles
}

violation contains {"field": "system", "msg": "granting a role to a group on the system requires system scope for manager role."} if {
        "manager" in input.credentials.roles
        input.credentials.system != "all"
}