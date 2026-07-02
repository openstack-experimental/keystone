# METADATA
# description: Policy for listing API Keys (SCIM ingress machine identities, ADR 0021)
package identity.api_key.list

import data.identity.api_key as api_key_common

# List ApiClientResources (ApiClientResourceListParameters).
#
# input.target.api_key fields:
#   domain_id:    string            Domain to list keys for (mandatory filter).
#   provider_id:  string (optional) Restrict to keys bound to this provider_id.
#   enabled:      bool (optional)   Restrict to enabled/disabled keys.
#
# input.existing is null.
#
# Rules (ADR 0021 §5.A): unlike `identity.user.list`, there is no `reader`
# carve-out -- listing API keys exposes metadata about machine-identity
# credentials and requires the same `manager`/`admin` bar as create/update/revoke.

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
	msg := "listing API keys for another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	api_key_common.own_key
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "listing API keys requires `manager` role."
}
