# METADATA
# description: Policy for bulk OAuth2 session revocation (ADR 0026 §9)
package identity.oauth2.revocation.create

# Revoke refresh token families of a user, a client or a whole domain
# (POST /v4/oauth2/{domain_id}/revocations).
#
# input.target.domain_id: string  Domain the revocation applies to (URL path).
# input.target.revocation: object  Request body.
#
# input.existing is null.
#
# A system admin may revoke in any domain; a domain `manager` only in the
# domain the token is scoped to.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	input.target.domain_id == input.credentials.domain_id
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": msg} if {
	input.target.domain_id != input.credentials.domain_id
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "revoking OAuth2 sessions in another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	input.target.domain_id == input.credentials.domain_id
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "revoking OAuth2 sessions requires `manager` role."
}
