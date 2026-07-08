# METADATA
# description: Policy for creating API Keys (SCIM ingress machine identities, ADR 0021)
package identity.api_key.create

import data.identity.api_key as api_key_common

# Create ApiClientResource (ApiClientResourceCreate).
#
# input.target.api_key fields:
#   domain_id:    string            Domain owning the machine identity.
#   provider_id:  string            ADR 0020 mapping provider_id the key authenticates against.
#   allowed_ips:  array (optional)  CIDR allowlist restricting the source IP.
#   description:  string (optional)
#   expires_at:   number            Mandatory TTL, UTC epoch seconds.
#
# input.existing is null.
#
# Rules (ADR 0021 §5.A): API key management requires the `manager` role
# (DomainManager) scoped to the key's own domain, or `admin` (SystemAdmin).
# There is no reader/list-only carve-out and no unscoped-`admin`-implies-any-domain
# ("DomainAdmin") shortcut -- cross-domain creation always requires `admin`.

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
	msg := "creating an API key for another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	api_key_common.own_key
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "creating an API key requires `manager` role."
}
