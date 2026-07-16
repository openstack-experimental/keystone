# METADATA
# description: Policy for listing node-local quorum-bypass emergency signing key candidates (ADR 0028 §6)
package identity.oauth2.key.list_local_emergency_candidates

# List local emergency candidates on the responding node (GET
# .../local-emergency-candidates), so an operator can see any
# LOCAL_EMERGENCY_CONFLICT before choosing which rotation_id to reconcile.
# SystemAdmin only, same posture as rotate_signing_key.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

violation contains {"field": "role", "msg": msg} if {
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "listing node-local emergency signing key candidates requires SystemAdmin."
}
