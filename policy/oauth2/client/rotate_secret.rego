# METADATA
# description: Policy for rotating an OAuth2 client's secret (ADR 0026 §5)
package identity.oauth2.client.rotate_secret

import data.identity.oauth2.client as client_common

# Rotate an OAuth2Client's secret (POST .../clients/{provider_id}/rotate-secret).
#
# input.target is null.
# input.existing.oauth2_client is the stored resource to rotate. A public
# client (`confidential == false`) has no `client_secret` to rotate -- the
# service layer (`Oauth2ClientService::rotate_secret`) already rejects this
# with a 422 `Validation` error, but the policy denies it too, up front and
# regardless of role, so the rejection shows up as a clear policy violation
# rather than only a provider-error message.

default allow := false

allow if {
	input.existing.oauth2_client.confidential
	"admin" in input.credentials.roles
}

allow if {
	input.existing.oauth2_client.confidential
	input.credentials.is_admin
}

allow if {
	input.existing.oauth2_client.confidential
	client_common.own_client
	"manager" in input.credentials.roles
}

violation contains {"field": "confidential", "msg": msg} if {
	not input.existing.oauth2_client.confidential
	msg := "cannot rotate a secret for a public OAuth2 client (no client_secret)."
}

violation contains {"field": "domain_id", "msg": msg} if {
	input.existing.oauth2_client.confidential
	client_common.foreign_client
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "rotating an OAuth2 client secret in another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	input.existing.oauth2_client.confidential
	client_common.own_client
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "rotating an OAuth2 client secret requires `manager` role."
}
