# METADATA
# description: Policy for viewing the OAuth2 settings of a domain (ADR 0043 §1)
package identity.oauth2.settings.show

import data.identity.oauth2.settings as settings_common

# Show the OAuth2 settings of a domain (GET .../settings).
#
# input.target is null.
# input.existing.oauth2_settings is the stored record (or the default of a
# domain that has none), which carries domain_id.

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
}

violation contains {"field": "domain_id", "msg": msg} if {
	settings_common.foreign_domain
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "showing the OAuth2 settings of another domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	settings_common.own_domain
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "showing the OAuth2 settings of a domain requires `manager` role."
}
