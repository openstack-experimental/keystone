# METADATA
# description: Policy for registering OAuth2 clients (relying parties, ADR 0026 §5)
package identity.oauth2.client.create

import data.identity.oauth2.client as client_common

# Create OAuth2Client (OAuth2ClientResourceCreate).
#
# input.target.domain_id:   string  Domain owning the registration (URL path).
# input.target.oauth2_client: object  OAuth2ClientCreate payload.
#
# input.existing is null.
#
# Rules (ADR 0026 §5, same tier structure as identity.api_key.create):
# client registration requires the `manager` role (DomainManager) scoped to
# the client's own domain, or `admin` (SystemAdmin). Registering a
# pre-authorized client always requires `admin`, regardless of domain.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	client_common.own_client
	"manager" in input.credentials.roles
	not input.target.oauth2_client.pre_authorized
}

violation contains {"field": "domain_id", "msg": msg} if {
	client_common.foreign_client
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "registering an OAuth2 client for another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	client_common.own_client
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "registering an OAuth2 client requires `manager` role."
}

violation contains {"field": "pre_authorized", "msg": msg} if {
	input.target.oauth2_client.pre_authorized
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "registering a pre_authorized OAuth2 client requires `admin` role."
}
