# METADATA
# title: Delete OAuth2 consent
# description: Policy for withdrawing a user's consent for an OAuth2 client (ADR 0026)
package identity.oauth2.consent.delete

# Withdraw the remembered consent of a user for a client. The handler also
# revokes the user's refresh token families of that client.
#
# input.target.user_id:   string  The user whose consent is withdrawn (URL path).
# input.target.client_id: string  The client (URL path).
# input.existing is null.
#
# A user may withdraw their own consent, but not through a delegation: the
# decision is keyed on the authentication chain (`is_delegated`), never on
# the token scope.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

# METADATA
# description: "A user may withdraw their own consent, but not through a delegation."
allow if {
	input.target.user_id == input.credentials.user_id
	not input.credentials.is_delegated
}

violation contains {"field": "user_id", "msg": msg} if {
	not allow
	msg := "withdrawing an OAuth2 consent requires being the user themselves (without a delegation) or the `admin` role."
}
