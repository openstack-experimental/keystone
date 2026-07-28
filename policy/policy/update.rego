# METADATA
# title: Update policy
# description: Policy for updating a legacy policy document
package identity.policy.update

import data.identity

# Update policy (legacy `PATCH /v3/policies/{policy_id}`).
#
# The `input.target.policy` contains the requested changes, projected onto the
# non-sensitive allowlist:
#   id:    string or null (optional)  Only accepted when equal to the path ID.
#   type:  string or null (optional)  New MIME media type.
#
# The document `blob` and any additional properties are deliberately NOT part
# of the input.
#
# The `input.existing.policy` is the stored policy under the same projection,
# or null if it does not exist.
#
# Mirrors python keystone's `identity:update_policy` (RULE_ADMIN_REQUIRED):
# admin only, no system-reader path.
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
