# METADATA
# description: Policy for deleting a dynamic auth plugin identity link
package identity.auth_plugin.identity_link.delete

import data.identity as common

# Delete an admin-authorized identity link (ADR 0025 §4). Same RBAC tiering
# as create: system-scope `admin` may unlink any user, including a system
# principal or one in another domain; a project/domain-scoped `admin` or
# `manager` may unlink only a non-system user in their own domain.
# `domain_id`/`is_system` may be null/false for a link whose target user was
# already deleted (stale-entry cleanup) - that collapses to the
# domain-scoped tier or system-scope `admin`.
#
# The `input.target.identity_link` is the identity link being deleted:
#   plugin_name:  string             The auth plugin the link belongs to.
#   user_id:      string             The Keystone user ID being unlinked.
#   domain_id:    string | null      The target user's own domain; null for
#                                    stale-entry cleanup after user deletion.
#   is_system:    boolean | null     Whether the target user holds a system
#   role; false/null for stale-entry cleanup.
#
# The `input.existing` is null.
#
#
# The `input.existing` is null.

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
	msg := "unlinking a user that holds a system-scope role requires the `admin` role on the system scope."
}

violation contains {"field": "domain_id", "msg": msg} if {
	input.target.identity_link.domain_id != input.credentials.domain_id
	not common.is_system_admin
	msg := "unlinking a user in another domain requires the `admin` role on the system scope."
}
