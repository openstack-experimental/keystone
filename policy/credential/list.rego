# METADATA
# title: List credentials
# description: Policy for listing credentials
package identity.credential.list

# List credentials.
#
# The `input.target.credential` contains query parameters:
#   type:    string (optional)  Filter by credential type.
#   user_id: string (optional)  Filter by owning user ID.
#
# The `input.existing` is null
#
# This is only the first of the two policy checks required to list
# credentials safely (ADR 0019 §2, CVE-2019-19687): the API layer
# additionally re-enforces `identity/credential/show` against every
# individual record before returning it, so this rule only needs to gate
# who may attempt a list at all.
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

allow if {
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

# METADATA
# description: "Any authenticated member may attempt to list; the per-item `identity/credential/show` re-check narrows the result to credentials they are actually allowed to read."
allow if {
	"member" in input.credentials.roles
}
