# METADATA
# title: List delegatable services
# description: Policy for listing the services a user may delegate to (ADR 0036 §3)
package identity.delegatable_service.list

# Any authenticated user may list the services it can name as a service
# grant grantee; the handler only returns the caller's domain's services
# and the cross-domain ones, without SPIFFE IDs. A service acting in the
# request (grantee or service client) has no use for it.
#
# The `input.target` is null; the `input.existing` is absent.
default allow := false

allow if {
	object.get(input.credentials, "actor", null) == null
	object.get(input.credentials, "service_grant_id", null) == null
	input.credentials.user_id != ""
}
