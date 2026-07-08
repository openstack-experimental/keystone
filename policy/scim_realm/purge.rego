# METADATA
# description: Policy for the operator-triggered erasure-request purge of a
#   single SCIM-provisioned resource, bypassing the janitor's configured
#   retention window (ADR 0024 §6.C, last paragraph).
package identity.scim_realm.purge

import data.identity

# Purge a single already-deprovisioned SCIM resource owned by a realm.
#
# The `input.existing.scim_realm` is the realm that owns the target
# resource -- the same authorization boundary as `identity/scim_realm/disable`,
# since purging a realm's resource is at least as sensitive as disabling the
# realm itself.
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

violation contains {"field": "domain_id", "msg": "purging a SCIM resource in a domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	input.existing.scim_realm.domain_id != input.credentials.domain_id
}

violation contains {"field": "domain_id", "msg": "purging a SCIM resource requires a manager role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}
