# METADATA
# description: Policy for reading the global domain configuration defaults
package identity.domain_config.get_default

# Read (GET) the global defaults a domain without its own configuration falls
# back to. The defaults hold no secrets.
#
# `input.target.group`  (optional) is the addressed group.
# `input.target.option` (optional) is the addressed option.
# `input.existing` is null.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

# Any authenticated reader may see the defaults.
allow if {
	"reader" in input.credentials.roles
}

# A domain manager may see the defaults.
allow if {
	"manager" in input.credentials.roles
}

violation contains {"field": "", "msg": "reading the domain configuration defaults requires an authenticated `reader`, `manager` or admin."} if {
	not allow
}
