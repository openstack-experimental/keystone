# METADATA
# title: Create service
# description: Policy for creating a catalog service
package identity.service.create

import data.identity

# Create service.
#
# The `input.target.service` is the new service object (ServiceCreate):
#   type:     string (optional)  The service type.
#   enabled:  bool               Whether the service appears in the catalog.
#   name:     string (optional)  The service name.
#
# The `input.existing` is null
#
default allow := false

# METADATA
# description: "`Admin` is allowed by default"
allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}
