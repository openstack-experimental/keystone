# METADATA
# title: Show trust
# description: Policy for fetching a single trust
package identity.trust.show

import data.identity.trust as trust_common

# Show trust.
#
# The `input.existing.trust` is the stored trust object (Trust), or null if
# not found -- see `identity/trust/create` for field shapes.
#
# The `input.target` is null
#
# This is also invoked by `identity/trust/list`'s per-item re-enforcement
# pass (ADR 0019 §2 pattern, CVE-2019-19687).
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
# description: "The trustor may always read a trust they created."
allow if {
	trust_common.is_trustor(input.existing.trust)
}

# METADATA
# description: "The trustee may always read a trust delegated to them."
allow if {
	trust_common.is_trustee(input.existing.trust)
}
