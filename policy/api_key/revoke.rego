# METADATA
# description: Policy for the API Key emergency revocation path (ADR 0021 §5.C)
package identity.api_key.revoke

import data.identity.api_key as api_key_common

# Revoke ApiClientResource (POST /v4/api-keys/{client_id}/revoke).
#
# input.target is null.
# input.existing.api_key is the stored ApiClientResource to be revoked.
#
# Revocation is the incident-response path (disable + tombstone, no hard
# delete) and holds to the same bar as create/update: `manager` scoped to
# the key's own domain, or `admin`.

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
	msg := "revoking an API key in another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	api_key_common.own_key
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "revoking an API key requires `manager` role."
}
