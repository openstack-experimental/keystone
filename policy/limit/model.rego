# METADATA
# title: Get limit enforcement model
# description: Policy for the discovery of the limit enforcement model
package identity.limit.model

# Get the limit enforcement model.
#
# The `input.target` and `input.existing` are null.
#
# The model is not tenant specific, therefore any caller holding a system,
# domain or project scoped token may read it.
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
# description: "Any caller holding a system, domain or project scoped token is allowed."
allow if {
	input.credentials.system != null
}

allow if {
	input.credentials.domain_id != null
}

allow if {
	input.credentials.project_id != null
}
