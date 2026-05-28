# METADATA
# description: Shared predicates for SPIFFE binding policies
package identity.spiffe

# Resolve binding domain_id from either target or existing input, depending
# on the operation (create/update vs. show/delete).
# Prefers existing.binding (for show/delete), falls back to target.binding
# (for create/list).
get_binding_domain_id := v if {
	input.existing.binding.domain_id
	v := input.existing.binding.domain_id
}

get_binding_domain_id := v if {
	input.target.binding.domain_id
	v := input.target.binding.domain_id
}

own_binding if {
	binding_domain_id := get_binding_domain_id()
	binding_domain_id != null
	binding_domain_id == input.credentials.domain_id
}

foreign_binding if {
	binding_domain_id := get_binding_domain_id()
	binding_domain_id != null
	binding_domain_id != input.credentials.domain_id
}

# Validate that all resources referenced in authorization scopes can be
# resolved. Produces violations when domain, project, or role lookups fail.
# Auths are serialized as tagged union (lowercase key):
#   {"domain": {"domain_id": "did", "domain": <null or object>,
#               "role_ids": [...], "roles": [<null or list>]}}
#   {"project": {"project_id": "pid", "project": <null or object>,
#                "role_ids": [...], "roles": [...]}}
#   {"system": {"system_id": "all", "role_ids": [...], "roles": [...]}}

authorization_domains_missing if {
	auths := input.target.binding.authorizations
	auths[_].domain.domain == null
}

authorization_projects_missing if {
	auths := input.target.binding.authorizations
	auths[_].project.project == null
}

authorization_roles_missing if {
	auths := input.target.binding.authorizations
	auth := auths[_]
	auth.domain
	auth.domain.roles != null
	count(auth.domain.role_ids) > count(auth.domain.roles)
}

authorization_roles_missing if {
	auths := input.target.binding.authorizations
	auth := auths[_]
	auth.project
	auth.project.roles != null
	count(auth.project.role_ids) > count(auth.project.roles)
}

authorization_roles_missing if {
	auths := input.target.binding.authorizations
	auth := auths[_]
	auth.system
	auth.system.roles != null
	count(auth.system.role_ids) > count(auth.system.roles)
}
