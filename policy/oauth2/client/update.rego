# METADATA
# description: Policy for updating OAuth2 clients (relying parties, ADR 0026 §5)
package identity.oauth2.client.update

import data.identity.oauth2.client as client_common

# Update OAuth2ClientResource (PUT .../clients/{provider_id}, OAuth2ClientUpdate).
#
# input.target.oauth2_client is the update patch (redirect_uris, grant_types,
# require_pkce, allowed_scopes, pre_authorized, enabled, claims_template).
# input.existing.oauth2_client is the stored resource, which carries
# domain_id -- the patch itself does not.
#
# ADR 0026 §5 deviation: even a domain-manager with otherwise-Tier-2 access
# must be denied when the patch sets pre_authorized == true, unless
# `admin`/`is_admin`. Also denied any edit to a client that is *already*
# pre_authorized == true, even one that doesn't touch that field itself --
# a manager could otherwise use e.g. `redirect_uris` on a pre-authorized
# (no interactive consent) client to widen where its tokens land, without
# ever needing to touch the `pre_authorized` field the admin-only gate
# actually watches.

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
	not input.existing.oauth2_client.pre_authorized
}

violation contains {"field": "domain_id", "msg": msg} if {
	client_common.foreign_client
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "updating an OAuth2 client in another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	client_common.own_client
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "updating an OAuth2 client requires `manager` role."
}

violation contains {"field": "pre_authorized", "msg": msg} if {
	input.target.oauth2_client.pre_authorized
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "setting pre_authorized on an OAuth2 client requires `admin` role."
}

violation contains {"field": "pre_authorized", "msg": msg} if {
	input.existing.oauth2_client.pre_authorized
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "editing an already pre_authorized OAuth2 client requires `admin` role."
}
