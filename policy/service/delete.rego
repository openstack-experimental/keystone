# METADATA
# title: Delete service
# description: Policy for deleting a catalog service
package identity.service.delete

import data.identity

# Delete service.
#
# The `input.existing.service` is the stored service object (Service):
#   id:       string            Service ID.
#   type:     string (optional) The service type.
#   enabled:  bool              Whether the service appears in the catalog.
#   name:     string (optional) The service name.
#
# The `input.target` is null
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
