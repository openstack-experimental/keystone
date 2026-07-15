# METADATA
# description: Policy for idempotently ensuring a domain's OAuth2 signing key exists (ADR 0026 §3)
package identity.oauth2.key.ensure_signing_key

# Ensure a domain's OAuth2 signing key exists (POST .../ensure-signing-key).
#
# SystemAdmin-only, same as rotate_signing_key: this is a bootstrap/repair
# operation for a domain that was created outside the Rust API's own
# `create_domain` event path (e.g. a domain provisioned by the legacy
# Python `keystone-manage bootstrap`, which never fires `Oauth2KeyHook`).

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
	msg := "ensuring an OAuth2 domain signing key requires SystemAdmin."
}
