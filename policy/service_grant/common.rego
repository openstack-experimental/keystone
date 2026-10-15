# METADATA
# title: Service grant helpers
# description: >
#   Shared predicates for identity.service_grant.* policies (ADR 0036 §4.2).
#   Delegation facts come from the authentication chain
#   (`input.credentials.delegated_project_id`, `actor`, `service_grant_id`),
#   never from the token scope alone (security model I2/I3).
package identity.service_grant

# METADATA
# description: "True when the caller holds `admin`."
is_admin if {
	"admin" in input.credentials.roles
}

is_admin if {
	input.credentials.is_admin
}

# METADATA
# description: >
#   True when the request is not itself made under a service grant. A
#   grant-derived request never manages grants, which keeps the delegation
#   chain at depth one.
not_under_service_grant if {
	object.get(input.credentials, "service_grant_id", null) == null
}

# METADATA
# description: "True when no delegatable service acts in the request."
no_actor if {
	object.get(input.credentials, "actor", null) == null
}

# METADATA
# description: >
#   True when `project_id` is the delegation's own immutable project, with
#   the token scope pinned to it as a scope-drift tripwire.
bound_to_own_delegation_project(project_id) if {
	project_id == input.credentials.delegated_project_id
	input.credentials.delegated_project_id != null
	input.credentials.project_id == input.credentials.delegated_project_id
}

# METADATA
# description: >
#   True when the caller is not delegated, or is delegated and `project_id`
#   is its delegation's own project. Callers pass a never-undefined value.
not_delegated_or_bound_to_own_project(_) if {
	not input.credentials.is_delegated
}

not_delegated_or_bound_to_own_project(project_id) if {
	input.credentials.is_delegated
	bound_to_own_delegation_project(project_id)
}

# METADATA
# description: "True when the caller is the grant's grantor."
is_grantor(grant) if {
	no_actor
	grant.grantor_user_id == input.credentials.user_id
}

# METADATA
# description: "True when the caller manages project `project_id`."
is_project_manager(project_id) if {
	no_actor
	"manager" in input.credentials.roles
	input.credentials.project_id != null
	input.credentials.project_id == project_id
}

# METADATA
# description: >
#   True when the caller manages domain `domain_id` with a domain-scoped,
#   non-delegated token.
is_domain_manager(domain_id) if {
	no_actor
	not input.credentials.is_delegated
	"manager" in input.credentials.roles
	input.credentials.domain_id != null
	input.credentials.domain_id == domain_id
}

# METADATA
# description: >
#   True when the caller is the grant's grantee service, authenticated by
#   its SVID against the grantee client (`service_client`).
is_grantee_service(grant) if {
	input.credentials.auth_type == "service_client"
	input.credentials.actor.client_id != null
	input.credentials.actor.client_id == grant.grantee.client_id
}

# METADATA
# description: >
#   True when the caller may read or delete `grant`: the grantor, a
#   manager of the grant's project, or of the grantor's or the project's
#   domain, an admin, or the grantee service.
may_manage(_) if {
	not_under_service_grant
	is_admin
}

may_manage(grant) if {
	not_under_service_grant
	is_grantor(grant)
	not_delegated_or_bound_to_own_project(object.get(grant, ["target", "project_id"], null))
}

may_manage(grant) if {
	not_under_service_grant
	is_project_manager(object.get(grant, ["target", "project_id"], null))
	not_delegated_or_bound_to_own_project(object.get(grant, ["target", "project_id"], null))
}

may_manage(grant) if {
	not_under_service_grant
	is_domain_manager(object.get(grant, "domain_id", null))
}

may_manage(grant) if {
	not_under_service_grant
	is_domain_manager(object.get(grant, ["target", "project_domain_id"], null))
}

may_manage(grant) if {
	is_grantee_service(grant)
}
