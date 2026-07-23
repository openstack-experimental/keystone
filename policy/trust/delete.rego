# METADATA
# title: Delete trust
# description: Policy for deleting a trust
package identity.trust.delete

import data.identity.trust as trust_common

# Delete trust.
#
# The `input.existing.trust` is the stored trust object (Trust), see
# `identity/trust/show`.
#
# The `input.target` is null
#
# Only the trustor (or admin) may delete a trust -- the trustee has no
# authority to revoke a delegation it did not grant.
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

# METADATA
# description: "The trustor may delete a trust they created."
allow if {
	"member" in input.credentials.roles
	trust_common.is_trustor(input.existing.trust)
}
