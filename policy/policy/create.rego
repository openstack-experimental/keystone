# METADATA
# title: Create policy
# description: Policy for creating a legacy policy document
package identity.policy.create

import data.identity

# Create policy (legacy `POST /v3/policies`).
#
# The `input.target.policy` is the new policy, projected onto the
# non-sensitive allowlist:
#   id:    null     Always null; the server assigns the ID.
#   type:  string   The MIME media type of the serialized blob.
#
# The document `blob` and any additional properties are deliberately NOT part
# of the input: they are arbitrary caller-supplied data that may contain
# secrets, and no rule here reads them.
#
# The `input.existing` is null
#
# Mirrors python keystone's `identity:create_policy` (RULE_ADMIN_REQUIRED):
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
