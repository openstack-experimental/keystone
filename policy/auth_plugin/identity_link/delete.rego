# METADATA
# description: Policy for deleting a dynamic auth plugin identity link
package identity.auth_plugin.identity_link.delete

# Delete an admin-authorized identity link (ADR 0025 §4). Same RBAC tiering
# as create: `admin` may unlink any user; `manager` may unlink only a
# non-system user in their own domain. `domain_id`/`is_system` may be null/
# false for a link whose target user was already deleted (stale-entry
# cleanup) - that collapses to the manager-in-own-domain path or `admin`.
#
# input.target.identity_link fields: plugin_name, user_id, domain_id,
# is_system (see create.rego).

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
	msg := "unlinking a user that holds a system-scope role requires `admin` role."
}

violation contains {"field": "domain_id", "msg": msg} if {
	input.target.identity_link.domain_id != input.credentials.domain_id
	not "admin" in input.credentials.roles
	msg := "unlinking a user in another domain requires `admin` role."
}
