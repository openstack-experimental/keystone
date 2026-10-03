# METADATA
# title: Update registered limit
# description: Policy for updating a registered limit
package identity.registered_limit.update

# Update registered limit.
#
# The `input.target.registered_limit` is the patch (RegisteredLimitUpdate):
#   service_id:     string (optional)  New service ID.
#   region_id:      string (optional)  New region ID.
#   resource_name:  string (optional)  New resource name.
#   default_limit:  integer (optional) New default limit.
#   description:    string (optional)  New description.
#
# The `input.existing.registered_limit` is the stored object (RegisteredLimit):
#   id:             string             Registered limit ID.
#   service_id:     string             The ID of the service.
#   region_id:      string (optional)  The ID of the region.
#   resource_name:  string             The name of the resource.
#   default_limit:  integer            The default limit value.
#   description:    string (optional)  The description.
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
