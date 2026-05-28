# METADATA
# description: Policy for updating SPIFFE bindings
package identity.spiffe.binding.update

import data.identity
import data.identity.spiffe as spiffe_common

# Update SPIFFE binding.

# The `input.target.binding` is the enriched update patch:
#   authorizations: [  optional list of authorization scopes
#     domain: {     domain-scoped authorization
#       domain_id:       string        domain ID
#       domain:          object|null   resolved Domain; null if not found or error
#       role_ids:        [string]      role IDs
#       roles:           [object]      resolved RoleRefs; missing roles skipped
#     }
#     project: {    project-scoped authorization
#       project_id:      string        project ID
#       project:         object|null   resolved Project; null if not found or error
#       role_ids:        [string]      role IDs
#       roles:           [object]      resolved RoleRefs; missing roles skipped
#     }
#     system: {     system-scoped authorization
#       system_id:       string        system identifier (e.g. "all")
#       role_ids:        [string]      role IDs
#       roles:           [object]      resolved RoleRefs; missing roles skipped
#     }
#   ]
#
# The `input.existing.binding` is the raw current binding (provider type):
#   domain_id:    string        domain ID of the binding
#   is_system:    boolean       whether the binding applies system-wide
#   svid:         string        SPIFFE SVID URL
#   user_id:      string|null   optional OpenStack user ID
#   authorizations: [...]       raw authorization scopes with string IDs

default allow := false

# Admin (admin role) can update bindings.
allow if {
	"admin" in input.credentials.roles
	not spiffe_common.authorization_domains_missing
	not spiffe_common.authorization_projects_missing
	not spiffe_common.authorization_roles_missing
}

# Admin (is_admin flag) can update bindings.
allow if {
	input.credentials.is_admin
	not spiffe_common.authorization_domains_missing
	not spiffe_common.authorization_projects_missing
	not spiffe_common.authorization_roles_missing
}

# System users (system == "all") with member role can update bindings.
allow if {
	"member" in input.credentials.roles
	input.credentials.system == "all"
	not spiffe_common.authorization_domains_missing
	not spiffe_common.authorization_projects_missing
	not spiffe_common.authorization_roles_missing
}

# Owner can update their own bindings.
allow if {
	"manager" in input.credentials.roles
	spiffe_common.own_binding
	not spiffe_common.authorization_domains_missing
	not spiffe_common.authorization_projects_missing
	not spiffe_common.authorization_roles_missing
}

violation contains {"field": "authorizations", "msg": msg} if {
	auths := input.target.binding.authorizations
	auth := auths[_]
	auth.domain
	auth.domain.domain == null
	msg := sprintf("authorization domain not found: %s", [auth.domain.domain_id])
}

violation contains {"field": "authorizations", "msg": msg} if {
	auths := input.target.binding.authorizations
	auth := auths[_]
	auth.project
	auth.project.project == null
	msg := sprintf("authorization project not found: %s", [auth.project.project_id])
}

violation contains {"field": "authorizations", "msg": "authorization roles not found"} if {
	spiffe_common.authorization_roles_missing
}

violation contains {"field": "domain_id", "msg": "updating SPIFFE binding for other domain requires `admin` role."} if {
	spiffe_common.foreign_binding
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
}

violation contains {"field": "role", "msg": "updating SPIFFE binding requires `manager` role."} if {
	spiffe_common.own_binding
	not "member" in input.credentials.roles
}
