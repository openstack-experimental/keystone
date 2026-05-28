# METADATA
# description: Policy for deleting SPIFFE bindings
package identity.spiffe.binding.delete

import data.identity
import data.identity.spiffe as spiffe_common

# Delete SPIFFE binding.

# The `input.target.binding` is null for delete operations.
#
# The `input.existing.binding` is the raw current binding (provider type):
#   domain_id:    string        domain ID of the binding
#   is_system:    boolean       whether the binding applies system-wide
#   svid:         string        SPIFFE SVID URL
#   user_id:      string|null   optional OpenStack user ID
#   authorizations: [...]       raw authorization scopes with string IDs

default allow := false

# Admin (admin role) can delete bindings.
allow if {
	"admin" in input.credentials.roles
}

# Admin (is_admin flag) can delete bindings.
allow if {
	input.credentials.is_admin
}

# System users (system == "all") with member role can delete bindings.
allow if {
	"member" in input.credentials.roles
	input.credentials.system == "all"
}

# Owner can delete their own bindings.
allow if {
	"manager" in input.credentials.roles
	spiffe_common.own_binding
}

violation contains {"field": "domain_id", "msg": "deleting SPIFFE binding for other domain requires `admin` role."} if {
	spiffe_common.foreign_binding
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
}

violation contains {"field": "role", "msg": "deleting SPIFFE binding requires `manager` role."} if {
	spiffe_common.own_binding
	not "member" in input.credentials.roles
}
