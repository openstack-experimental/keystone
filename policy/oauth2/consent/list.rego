# METADATA
# title: List OAuth2 consents
# description: Policy for listing the OAuth2 clients a user has approved (ADR 0026)
package identity.oauth2.consent.list

# List the remembered OAuth2 consents ("connected applications") of a user.
#
# input.target.user_id: string  The user whose consents are listed (URL path).
# input.existing is null.
#
# Every item of the response belongs to that one user, so this check covers
# every item; there is no per-item decision that could differ.
#
# A user may list their own consents. A caller acting through a delegation
# (application credential, trust) may not: the decision is keyed on the
# authentication chain (`is_delegated`), never on the token scope.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

# METADATA
# description: "A user may list their own consents, but not through a delegation."
allow if {
	input.target.user_id == input.credentials.user_id
	not input.credentials.is_delegated
}

violation contains {"field": "user_id", "msg": msg} if {
	not allow
	msg := "listing OAuth2 consents requires being the user themselves (without a delegation) or the `admin` role."
}
