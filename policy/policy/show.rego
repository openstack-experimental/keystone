# METADATA
# title: Show policy
# description: Policy for fetching a single legacy policy document
package identity.policy.show

import data.identity

# Show policy (legacy `GET /v3/policies/{policy_id}`).
#
# Also re-checked per item by the list handler (security model I8), so a
# caller only ever sees collection members this rule admits.
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
# Mirrors python keystone's `identity:get_policy`
# (RULE_ADMIN_OR_SYSTEM_READER).
#
# NOTE on the credentials key: the system scope arrives as
# `input.credentials.system` (`Credentials.system` in
# `crates/core/src/policy.rs`, serialized under its own field name). Several
# older policies in this tree compare against `input.credentials.system_scope`,
# a key `Credentials` never emits, which makes their system-reader branches
# unreachable against real input — their Rego unit tests only pass because they
# hand-write that key. Do not copy that spelling here.
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
# description: "'reader' in the system scope can show any policy."
allow if {
	"reader" in input.credentials.roles
	input.credentials.system != null
	"all" == input.credentials.system
}
