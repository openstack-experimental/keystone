# METADATA
# title: List policies
# description: Policy for listing legacy policy documents
package identity.policy.list

import data.identity

# List policies (legacy `GET /v3/policies`).
#
# NOTE: this governs the deprecated `/v3/policies` *document store*, not this
# service's own authorization. A stored "policy" is opaque data a remote
# service fetches; Keystone never evaluates it.
#
# The `input.target.policy` contains the query parameters, projected onto the
# non-sensitive allowlist (see `crates/api-types/src/v3/policy.rs`):
#   id:    null                      Always null when listing.
#   type:  string or null (optional)  Exact-match filter on the blob media type.
#
# The document `blob` and any additional properties are deliberately NOT part
# of the input: they are arbitrary caller-supplied data no rule here reads.
#
# The `input.existing` is null
#
# Mirrors python keystone's `identity:list_policies`
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
# description: "'reader' in the system scope can list any policies."
allow if {
	"reader" in input.credentials.roles
	input.credentials.system != null
	"all" == input.credentials.system
}
