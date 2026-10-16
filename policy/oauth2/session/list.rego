# METADATA
# description: Policy for listing the OAuth2 sessions of a user (ADR 0026 §9)
package identity.oauth2.session.list

# List the refresh token families of a user
# (GET /v4/oauth2/{domain_id}/sessions).
#
# input.target.domain_id: string  Domain of the sessions (URL path).
# input.target.user_id: string  User whose sessions are listed.
#
# input.existing is null.
#
# A system admin may list in any domain; a domain `manager` only in the
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
	msg := "listing OAuth2 sessions in another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	input.target.domain_id == input.credentials.domain_id
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "listing OAuth2 sessions requires `manager` role."
}
