# METADATA
# description: Policy for the API Key dry-run auditing endpoint (ADR 0021 §5.E)
package identity.api_key.simulate_access

import data.identity.api_key as api_key_common

# Simulate access for an ApiClientResource (POST /v4/api-keys/simulate-access).
#
# input.target is null.
# input.existing.api_key is the stored ApiClientResource resolved server-side
# from the `client_id` given in the request body (kept out of the URL/query
# string to avoid leaking it into proxy access logs, per ADR 0021 §5.E).
#
# This performs a mock authentication pass and returns the key's fully
# resolved authorization topology, so it holds to the same bar as the other
# admin actions: `manager` scoped to the key's own domain, or `admin`.

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
	msg := "simulating access for an API key in another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	api_key_common.own_key
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "simulating access for an API key requires `manager` role."
}
