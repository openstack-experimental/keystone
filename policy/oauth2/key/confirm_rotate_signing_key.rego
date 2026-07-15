# METADATA
# description: Policy for confirming a pending emergency signing key rotation (ADR 0026 §3)
package identity.oauth2.key.confirm_rotate_signing_key

# Confirm stage 2 of an emergency rotation (POST
# .../confirm-rotate-signing-key). SystemAdmin only, same posture as
# rotate_signing_key -- the dual-control "confirmer != initiator" check
# itself is enforced by the provider layer (it needs the stored initiator
# identity, which is not policy input), not by this policy.

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
	msg := "confirming an OAuth2 emergency signing key rotation requires SystemAdmin."
}
