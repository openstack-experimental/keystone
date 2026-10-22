# METADATA
# description: Policy for updating the OAuth2 settings of a domain (ADR 0043 §1)
package identity.oauth2.settings.update

import data.identity.oauth2.settings as settings_common

# Update the OAuth2 settings of a domain (PUT .../settings).
#
# input.target.oauth2_settings is the resulting state: `dpop` is the mode the
# domain ends up with (the stored one when the request leaves it out) and
# `global_dpop` the global `[oauth2] dpop` floor.
# input.existing.oauth2_settings is the stored record, which carries
# domain_id.
#
# ADR 0043 §1: raising the mode is self-service for the domain `manager`.
# Lowering it, or setting it below the global value, requires
# `admin`/`is_admin`, so that a compromised domain manager cannot disable
# DPoP.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	settings_common.own_domain
	"manager" in input.credentials.roles
	not settings_common.dpop_lowered
	not settings_common.dpop_below_global
}

violation contains {"field": "domain_id", "msg": msg} if {
	settings_common.foreign_domain
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "updating the OAuth2 settings of another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	settings_common.own_domain
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "updating the OAuth2 settings of a domain requires `manager` role."
}

violation contains {"field": "dpop", "msg": msg} if {
	settings_common.dpop_lowered
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "lowering the DPoP mode of a domain requires `admin` role."
}

violation contains {"field": "dpop", "msg": msg} if {
	settings_common.dpop_below_global
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "setting the DPoP mode of a domain below the global mode requires `admin` role."
}
