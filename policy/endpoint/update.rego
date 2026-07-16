# METADATA
# title: Update endpoint
# description: Policy for updating a catalog endpoint
package identity.endpoint.update

import data.identity

# Update endpoint.
#
# The `input.target.endpoint` contains the fields to change (EndpointUpdate):
#   interface:   string (optional)  New interface.
#   region_id:   string (optional)  New region ID.
#   service_id:  string (optional)  New service ID.
#   url:         string (optional)  New endpoint URL.
#   enabled:     bool (optional)    New enabled flag.
#
# The `input.existing.endpoint` is the stored endpoint object (Endpoint), or
# null if it does not exist.
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
