# METADATA
# description: Policy for listing SPIFFE bindings
package identity.spiffe.binding.list

import data.identity
import data.identity.spiffe as spiffe_common

# List SPIFFE bindings.

# The `input.target.binding` is the list query parameters:
#   domain_id:    string|null   filter by domain ID
#   user_id:      string|null   filter by user ID
#
# The `input.existing` is null for list operations.

default allow := false

# Admin (admin role) can list bindings.
allow if {
	"admin" in input.credentials.roles
}

# Admin (is_admin flag) can list bindings.
allow if {
	input.credentials.is_admin
}

# System users (system == "all") with member role can list bindings.
allow if {
	"member" in input.credentials.roles
	input.credentials.system == "all"
}

# Owner can list their own bindings.
allow if {
	"reader" in input.credentials.roles
	spiffe_common.own_binding
}

# Allow listing when the domain_id is unset. Code is responsible for setting
# domain_id to the current one.
allow if {
	input.target.binding.domain_id == null
	"reader" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "listing SPIFFE bindings for other domain requires `admin` role."} if {
	spiffe_common.foreign_binding
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
}

violation contains {"field": "role", "msg": "listing SPIFFE bindings requires `reader` role."} if {
	spiffe_common.own_binding
	not "reader" in input.credentials.roles
}
