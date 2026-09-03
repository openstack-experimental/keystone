# METADATA
# description: Policy for deleting a domain's configuration
package identity.domain_config.delete

# Delete (DELETE) the whole configuration of a domain, a single group or a
# single option.
#
# `input.target.domain_id` is the domain being configured.
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

# A domain manager may configure the domain their token is scoped to.
allow if {
	"manager" in input.credentials.roles
	input.credentials.domain_id == input.target.domain_id
}

violation contains {"field": "", "msg": "deleting a domain configuration requires system admin or the `manager` role on the domain."} if {
	not allow
}
