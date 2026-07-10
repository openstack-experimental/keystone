# METADATA
# description: Policy for creating a dynamic auth plugin identity link
package identity.auth_plugin.identity_link.create

import data.identity as common

# Create an admin-authorized (plugin_name, external_id) -> user_id link
# (ADR 0025 §4 "Admin-Authorized External Identity Linking").
#
# The `input.target.identity_link` is the new identity link object:
#   plugin_name:  string             The auth plugin the link belongs to.
#   user_id:      string             The Keystone user ID being linked.
#   domain_id:    string | null      The target user's own domain.
#   is_system:    boolean            Whether the target user holds any
#                                    system-scope role.
#
# The `input.existing` is null.
#
# Rules (ADR §4: system-admin required for a system-role target;
# domain-admin scoped to the target's own domain suffices otherwise):
# - System-scope `admin` may link any user, including a system principal or
#   one in another domain.
# - A project/domain-scoped `admin` or `manager` may link only a non-system
#   user in their own domain - a project-scoped `admin` is NOT sufficient to
#   link a system-role-holding user or one in a different domain.

default allow := false

allow if {
	input.credentials.is_admin
}

allow if {
	common.is_system_admin
}

allow if {
	not input.target.identity_link.is_system
	input.target.identity_link.domain_id == input.credentials.domain_id
	"admin" in input.credentials.roles
}

allow if {
	not input.target.identity_link.is_system
	input.target.identity_link.domain_id == input.credentials.domain_id
	"manager" in input.credentials.roles
}

violation contains {"field": "is_system", "msg": msg} if {
	input.target.identity_link.is_system
	not common.is_system_admin
	msg := "linking a user that holds a system-scope role requires the `admin` role on the system scope."
}

violation contains {"field": "domain_id", "msg": msg} if {
	input.target.identity_link.domain_id != input.credentials.domain_id
	not common.is_system_admin
	msg := "linking a user in another domain requires the `admin` role on the system scope."
}
