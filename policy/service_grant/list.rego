# METADATA
# title: List service grants
# description: Policy for listing service grants (ADR 0036 §4.2)
package identity.service_grant.list

import data.identity.service_grant as sg

# The `input.target.service_grant` is the list filter set
# (ServiceGrantListParameters): user_id, project_id, domain_id,
# grantee_client_id, enabled -- all optional.
#
# The `input.existing` is null.
#
# Without `admin` a filter naming the caller's own reach is required
# (security model I8a); every returned grant is then re-checked with
# `identity/service_grant/show`. The grantee service cannot list.
default allow := false

filter(name) := object.get(input.target.service_grant, name, null)

allow if {
	sg.not_under_service_grant
	sg.is_admin
}

# The grantor's own grants.
allow if {
	sg.not_under_service_grant
	sg.no_actor
	filter("user_id") == input.credentials.user_id
	sg.not_delegated_or_bound_to_own_project(filter("project_id"))
}

# The grants on a project the caller manages.
allow if {
	sg.not_under_service_grant
	sg.is_project_manager(filter("project_id"))
	sg.not_delegated_or_bound_to_own_project(filter("project_id"))
}

# The grants of a domain the caller manages.
allow if {
	sg.not_under_service_grant
	sg.is_domain_manager(filter("domain_id"))
}
