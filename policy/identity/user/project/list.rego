# METADATA
# description: Policy for listing projects of a user
package identity.user.project.list

import data.identity

# List projects a user has a role assignment on.
#
# Protects `GET /v3/users/{user_id}/projects` and
# `GET /v4/users/{user_id}/projects`.
#
# The `input.existing.user` is the stored user object whose projects are
# listed (User):
#   domain_id: string  User domain ID.
#   id:        string  User ID.
#
# The `input.target` is null
#
# Mirrors the Python Keystone `identity:list_user_projects` rule: admin,
# system reader, domain reader of the user's domain, or the user itself.
# The "user itself" shortcut is never granted to delegated callers
# (trust, application credential, EC2): the decision is keyed on the
# authentication chain (`is_delegated`), not on the token scope.
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

allow if {
	"reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}

allow if {
	not input.credentials.is_delegated
	input.credentials.user_id == input.existing.user.id
}

violation contains {"field": "user_id", "msg": "listing projects of a user requires `admin`, a `reader` role with system or the user domain scope, or being the user itself."} if {
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	not "reader" in input.credentials.roles
	not input.credentials.user_id == input.existing.user.id
}
