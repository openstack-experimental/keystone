# METADATA
# description: Policy for viewing SPIFFE binding details
package identity.spiffe.binding.show

import data.identity
import data.identity.spiffe as spiffe_common

# Show SPIFFE binding.

# The `input.target.binding` is null for show operations.
#
# The `input.existing.binding` is the raw current binding (provider type):
#   domain_id:    string        domain ID of the binding
#   is_system:    boolean       whether the binding applies system-wide
#   svid:         string        SPIFFE SVID URL
#   user_id:      string|null   optional OpenStack user ID
#   authorizations: [...]       raw authorization scopes with string IDs

default allow := false

# Admin (admin role) can show bindings.
allow if {
	"admin" in input.credentials.roles
}

# Admin (is_admin flag) can show bindings.
allow if {
	input.credentials.is_admin
}

# System users (system == "all") with member role can show bindings.
allow if {
	"member" in input.credentials.roles
	input.credentials.system == "all"
}

# Owner can show their own bindings.
allow if {
	"reader" in input.credentials.roles
	spiffe_common.own_binding
}

violation contains {"field": "domain_id", "msg": "showing SPIFFE binding for other domain requires `admin` role."} if {
	spiffe_common.foreign_binding
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
}

violation contains {"field": "role", "msg": "showing SPIFFE binding requires `reader` role."} if {
	spiffe_common.own_binding
	not "reader" in input.credentials.roles
	not "member" in input.credentials.roles
}
