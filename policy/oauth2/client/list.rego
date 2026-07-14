# METADATA
# description: Policy for listing OAuth2 clients (relying parties, ADR 0026 §5)
package identity.oauth2.client.list

import data.identity.oauth2.client as client_common

# List OAuth2ClientResources.
#
# input.target.domain_id: string  Domain to list clients for (URL path).
# input.existing is null.

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
	msg := "listing OAuth2 clients for another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	client_common.own_client
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "listing OAuth2 clients requires `manager` role."
}
