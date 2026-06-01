# METADATA
# description: Policy for deleting domains
package identity.resource.domain.delete

import data.identity

# Delete a domain.
#
# The `input.target` is null.
# The `input.existing.domain` is the stored resource object (Domain):
#   description: string (optional)  The domain description.
#   enabled:     bool               Whether the domain is enabled.
#   id:          string             The domain ID.
#   name:        string             The domain name.
#
default allow := false

allow if {
	input.credentials.is_admin
}

allow if {
	"admin" in input.credentials.roles
}

violation contains {"field": "", "msg": "deleting domains requires system admin privileges."} if {
	not input.credentials.is_admin
}
