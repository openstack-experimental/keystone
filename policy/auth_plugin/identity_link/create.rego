# METADATA
# description: Policy for creating a dynamic auth plugin identity link
package identity.auth_plugin.identity_link.create

# Create an admin-authorized (plugin_name, external_id) -> user_id link
# (ADR 0025 §4 "Admin-Authorized External Identity Linking").
#
# input.target.identity_link fields:
#   plugin_name:  string
#   user_id:      string
#   domain_id:    string | null   -- the target user's own domain
#   is_system:    boolean         -- target holds any system-scope role
#
# Rules (RBAC-tiered as ADR 0020 §9.A gates mapping writes):
# - `admin` may link any user, including a system principal or one in
#   another domain.
# - `manager` may link only a non-system user in their own domain.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	not input.target.identity_link.is_system
	input.target.identity_link.domain_id == input.credentials.domain_id
	"manager" in input.credentials.roles
}

violation contains {"field": "is_system", "msg": msg} if {
	input.target.identity_link.is_system
	not "admin" in input.credentials.roles
	msg := "linking a user that holds a system-scope role requires `admin` role."
}

violation contains {"field": "domain_id", "msg": msg} if {
	input.target.identity_link.domain_id != input.credentials.domain_id
	not "admin" in input.credentials.roles
	msg := "linking a user in another domain requires `admin` role."
}
