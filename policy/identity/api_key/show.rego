# METADATA
# description: Policy for viewing a single API Key's metadata (ADR 0021)
package identity.api_key.show

import data.identity.api_key as api_key_common

# Show a single ApiClientResource (GET /v4/api-keys/{client_id}).
#
# input.target is null.
# input.existing.api_key is the stored ApiClientResource.
#
# Not explicitly enumerated in ADR 0021 §5.A, but held to the same bar as
# `identity.api_key.list` for consistency: no `reader` carve-out, since the
# response describes a machine-identity credential's configuration.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	api_key_common.own_key
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": msg} if {
	api_key_common.foreign_key
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "showing an API key in another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	api_key_common.own_key
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "showing an API key requires `manager` role."
}
