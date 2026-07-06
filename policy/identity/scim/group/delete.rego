# METADATA
# description: Policy for neutralizing/tombstoning a SCIM-provisioned group (ADR 0024 §3, §6.B, §8)
package identity.scim.group.delete

import data.identity

# `DELETE` (neutralize + tombstone) a SCIM-provisioned group.
#
# The `input.existing.group` is the stored `Group`.
#
# The Ownership Fencing Algorithm (ADR 0024 §3.C) has already run in the
# handler before this policy is evaluated — this is a second, independent
# authorization check, not a substitute for it (§8).
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	"manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}

allow if {
	"scim_provisioner" in input.credentials.roles
	identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "deleting a SCIM group in a domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "roles", "msg": "deleting a SCIM group requires a scim_provisioner or manager role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	not "scim_provisioner" in input.credentials.roles
	identity.domain_matches_domain_scope
}
