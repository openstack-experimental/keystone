# METADATA
# description: Policy for updating API Keys (SCIM ingress machine identities, ADR 0021)
package identity.api_key.update

import data.identity.api_key as api_key_common

# Update ApiClientResource (PUT /v4/api-keys/{client_id}, ApiClientResourceUpdate).
#
# input.target.api_key is the update patch:
#   allowed_ips:  array or null (optional)  New CIDR allowlist, or null to clear.
#   description:  string or null (optional) New description, or null to clear.
#   enabled:      bool (optional)           New enabled state.
#
# input.existing.api_key is the stored ApiClientResource, which carries
# domain_id -- the patch itself does not.

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
	msg := "updating an API key in another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	api_key_common.own_key
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "updating an API key requires `manager` role."
}
