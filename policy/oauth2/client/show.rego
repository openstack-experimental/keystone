# METADATA
# description: Policy for viewing a single OAuth2 client's metadata (ADR 0026 §5)
package identity.oauth2.client.show

import data.identity.oauth2.client as client_common

# Show a single OAuth2ClientResource (GET .../clients/{provider_id}).
#
# input.target is null.
# input.existing.oauth2_client is the stored resource (never carries
# client_secret_hash).

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
}

violation contains {"field": "domain_id", "msg": msg} if {
	client_common.foreign_client
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "showing an OAuth2 client in another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	client_common.own_client
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "showing an OAuth2 client requires `manager` role."
}
