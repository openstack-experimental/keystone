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

# A domain manager may configure the domain their token is scoped to, except
# the `assignment` group: binding a domain to an assignment backend is a
# role-minting surface reserved for cloud admins (ADR 0034 §6). A whole-config
# DELETE carries no group, so a manager can still drop their domain's whole
# configuration — that only reverts the domain to the global driver, which
# mints nothing.
allow if {
	"manager" in input.credentials.roles
	input.credentials.domain_id == input.target.domain_id
	not touches_assignment_group
}

# The delete addresses the `assignment` group directly (group or option path).
touches_assignment_group if {
	input.target.group == "assignment"
}

violation contains {"field": "", "msg": "deleting a domain configuration requires system admin or the `manager` role on the domain."} if {
	not allow
}
