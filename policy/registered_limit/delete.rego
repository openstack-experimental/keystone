# METADATA
# title: Delete registered limit
# description: Policy for deleting a registered limit
package identity.registered_limit.delete

# Delete registered limit.
#
# The `input.existing.registered_limit` is the stored object (RegisteredLimit):
#   id:             string             Registered limit ID.
#   service_id:     string             The ID of the service.
#   region_id:      string (optional)  The ID of the region.
#   resource_name:  string             The name of the resource.
#   default_limit:  integer            The default limit value.
#   description:    string (optional)  The description.
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
