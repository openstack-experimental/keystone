# METADATA
# title: Update service
# description: Policy for updating a catalog service
package identity.service.update

import data.identity

# Update service.
#
# The `input.target.service` contains the fields to change (ServiceUpdate):
#   type:     string (optional)  New service type.
#   enabled:  bool (optional)    New enabled flag.
#   name:     string (optional)  New service name.
#
# The `input.existing.service` is the stored service object (Service), or
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
