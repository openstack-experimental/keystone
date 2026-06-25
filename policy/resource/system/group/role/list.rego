# METADATA
# description: Policy for listing roles of a group on system
package identity.system.group.role.list

import data.identity

default allow := false

allow if {
        "admin" in input.credentials.roles
}

allow if {
        input.credentials.is_admin
}

allow if {
        "reader" in input.credentials.roles
        input.credentials.system == "all"
}

violation contains {"field": "system", "msg": "listing system-group-role assignment requires admin role."} if {
        not "admin" in input.credentials.roles
}

violation contains {"field": "system", "msg": "listing system-group-role assignment requires system scope for reader role."} if {
        "reader" in input.credentials.roles
        input.credentials.system != "all"
}