# METADATA
# description: Policy for updating domains
package identity.resource.domain.update

import data.identity

# Update a domain.
#
# The `input.target.domain` is the update patch (DomainUpdate):
#   description: string (optional)  The domain description.
#   enabled:     bool (optional)    Whether the domain is enabled.
#   name:        string (optional)  The domain name.
#
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

violation contains {"field": "", "msg": "updating domains requires system admin privileges."} if {
	not input.credentials.is_admin
}
