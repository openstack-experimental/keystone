# METADATA
# title: List trusts
# description: Policy for listing trusts
package identity.trust.list

# List trusts.
#
# The `input.target.trust` contains query parameters.
#
# The `input.existing` is null
#
# This is only the first of the two policy checks required to list trusts
# safely (ADR 0019 §2 pattern, CVE-2019-19687): the API layer additionally
# re-enforces `identity/trust/show` against every individual record before
# returning it, so this rule only needs to gate who may attempt a list at
# all -- the trustor/trustee narrowing happens entirely in that per-item
# re-check.
#
default allow := false

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
# description: "Any authenticated member may attempt to list; the per-item `identity/trust/show` re-check narrows the result to trusts they are the trustor or trustee of."
allow if {
	"member" in input.credentials.roles
}
