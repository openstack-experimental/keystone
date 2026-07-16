# METADATA
# title: Show endpoint
# description: Policy for fetching a single catalog endpoint
package identity.endpoint.show

import data.identity

# Show endpoint.
#
# The `input.existing.endpoint` is the stored endpoint object (Endpoint):
#   id:          string            Endpoint ID.
#   interface:   string            The interface (public, internal, admin).
#   region_id:   string (optional) The ID of the region.
#   service_id:  string            The UUID of the service.
#   url:         string            The endpoint URL.
#   enabled:     bool              Whether the endpoint appears in the catalog.
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

# METADATA
# description: "'reader' in the system scope can show any endpoint."
allow if {
	"reader" in input.credentials.roles
	input.credentials.system_scope != null
	"all" == input.credentials.system_scope
}
