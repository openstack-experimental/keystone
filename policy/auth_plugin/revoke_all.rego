# METADATA
# description: Policy for bulk-revoking a dynamic auth plugin's state
package identity.auth_plugin.revoke_all

# Bulk revocation of a compromised full_auth plugin's persistent state
# (ADR 0025 §4 "Bulk Revocation on Plugin Compromise"). System-admin ONLY -
# this is a cross-domain action by construction (a plugin's provisioning
# domains and role grants can span any domain), so unlike identity-link
# create/delete there is no domain-scoped `manager` tier.
#
# input.target.plugin_name: the plugin whose state is being revoked.

default allow := false

allow if {
	"admin" in input.credentials.roles
	input.credentials.system == "all"
}

violation contains {"field": "system", "msg": msg} if {
	not allow
	msg := "bulk plugin revocation requires the `admin` role on the system scope."
}
