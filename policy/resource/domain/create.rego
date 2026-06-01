# METADATA
# description: Policy for creating domains
package identity.resource.domain.create

import data.identity

# Create a new domain
#
# The `input.target.domain` is the new domain object (DomainCreate):
#   description:  string (optional)  The description of the domain.
#   enabled:      bool              If set to true, domain is enabled.
#   id:           string (optional)  The domain ID.
#   name:         string            The domain name.
#
# The `input.existing` is null
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

violation contains {"field": "", "msg": "creating domains requires system admin privileges."} if {
	not input.credentials.is_admin
}
