# METADATA
# description: Policy for reconciling a node-local quorum-bypass emergency signing key rotation (ADR 0028 §6)
package identity.oauth2.key.reconcile_local_emergency_key

# Reconcile a `--local-quorum-bypass` candidate into Raft-replicated state
# (POST .../reconcile-local-emergency-key). SystemAdmin only, same posture as
# rotate_signing_key/confirm_rotate_signing_key -- the dual-control
# "confirmer != initiator" check itself is enforced by the provider layer
# (it needs the stored initiator identity, which is not policy input), not
# by this policy.

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
	msg := "reconciling a node-local emergency signing key rotation requires SystemAdmin."
}
