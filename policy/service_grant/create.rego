# METADATA
# title: Create service grant
# description: Policy for creating a service grant (ADR 0036 §4.1)
package identity.service_grant.create

import data.identity.service_grant as sg

# The `input.target.service_grant` is the ServiceGrantCreate payload:
#   grantee_client_id: string
#   project_id:        string
#   role_ids:          array (optional)
#   expires_at:        string (optional)
#   description:       string (optional)
#
# The `input.existing` is null.
#
# The caller is always the grantor and delegates only its own roles, so
# there is no role requirement and no admin bypass. A delegated chain may
# not delegate further (trust, restricted application credential, service
# grant); an unrestricted application credential may, on its own project
# only. The provider repeats these checks.
default allow := false

allow if {
	sg.no_actor
	sg.not_under_service_grant
	not input.credentials.is_delegated
}

allow if {
	sg.no_actor
	sg.not_under_service_grant
	input.credentials.is_delegated
	input.credentials.auth_type == "application_credential"
	input.credentials.unrestricted == true
	sg.bound_to_own_delegation_project(object.get(input.target.service_grant, "project_id", null))
}
