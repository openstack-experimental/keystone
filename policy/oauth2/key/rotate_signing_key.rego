# METADATA
# description: Policy for rotating a domain's OAuth2 signing key (ADR 0026 §3)
package identity.oauth2.key.rotate_signing_key

# Rotate a domain's OAuth2 signing key (POST .../rotate-signing-key).
#
# ADR 0026 §3 requires SystemAdmin for both normal and emergency rotation --
# unlike OAuth2Client CRUD, there is no Tier 2 domain-manager self-service
# path here: a compromised or misused signing key affects every token the
# domain has ever issued, not a single client registration.

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
	msg := "rotating an OAuth2 domain signing key requires SystemAdmin."
}
