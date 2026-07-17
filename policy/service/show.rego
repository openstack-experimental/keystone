# METADATA
# title: Show service
# description: Policy for fetching a single catalog service
package identity.service.show

import data.identity

# Show service.
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

# METADATA
# description: "'reader' in the system scope can show any service."
allow if {
	"reader" in input.credentials.roles
	input.credentials.system != null
	"all" == input.credentials.system
}
