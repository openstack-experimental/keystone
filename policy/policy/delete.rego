# METADATA
# title: Delete policy
# description: Policy for deleting a legacy policy document
package identity.policy.delete

import data.identity

# Delete policy (legacy `DELETE /v3/policies/{policy_id}`).
#
# The `input.existing.policy` is the stored policy, projected onto the
# non-sensitive allowlist:
#   id:    string   Policy ID.
#   type:  string   The MIME media type of the serialized blob.
#
# The document `blob` and any additional properties are deliberately NOT part
# of the input.
#
# The `input.target` is null
#
# Mirrors python keystone's `identity:delete_policy` (RULE_ADMIN_REQUIRED):
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
