# METADATA
# description: Policy for reading a domain's configuration
package identity.domain_config.show

# Read (GET) the whole configuration of a domain, a single group or a single
# option.
#
# `input.target.domain_id` is the domain being read.
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

# A system reader may read any domain's configuration.
allow if {
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

# A domain manager may read the domain their token is scoped to.
allow if {
	"manager" in input.credentials.roles
	input.credentials.domain_id == input.target.domain_id
}

violation contains {"field": "", "msg": "reading a domain configuration requires system admin, the `reader` role with system scope, or the `manager` role on the domain."} if {
	not allow
}
