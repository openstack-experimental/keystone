# METADATA
# title: Create endpoint
# description: Policy for creating a catalog endpoint
package identity.endpoint.create

import data.identity

# Create endpoint.
#
# The `input.target.endpoint` is the new endpoint object (EndpointCreate):
#   interface:   string            The interface (public, internal, admin).
#   region_id:   string (optional) The ID of the region.
#   service_id:  string            The UUID of the service.
#   url:         string            The endpoint URL.
#   enabled:     bool              Whether the endpoint appears in the catalog.
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
