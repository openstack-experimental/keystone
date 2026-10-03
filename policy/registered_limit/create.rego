# METADATA
# title: Create registered limits
# description: Policy for creating registered limits (batch)
package identity.registered_limit.create

# Create registered limits.
#
# Invoked once per item of the batch. The `input.target.registered_limit` is
# the new registered limit (RegisteredLimitCreate):
#   service_id:     string             The ID of the service.
#   region_id:      string (optional)  The ID of the region.
#   resource_name:  string             The name of the resource.
#   default_limit:  integer            The default limit value.
#   description:    string (optional)  The description.
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
