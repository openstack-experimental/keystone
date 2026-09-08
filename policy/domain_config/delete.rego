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

# The configured admin SVID (system-level operator) may delete any group.
allow if {
	input.credentials.is_admin
}

# A system-scoped `admin` — a cloud administrator — may delete any group,
# including `assignment` (ADR 0034 §6).
allow if {
	"admin" in input.credentials.roles
	input.credentials.system == "all"
}

# An `admin` on any other scope may delete any group EXCEPT `assignment`, which
# is reserved for cloud admins and must not be satisfiable by a domain- or
# project-scoped token (ADR 0034 §6). A whole-config DELETE carries no group,
# so it is still reachable — that only reverts the domain to the global driver,
# which mints nothing.
allow if {
	"admin" in input.credentials.roles
	not touches_assignment_group
}

# A domain manager may drop the configuration of the domain their token is
# scoped to, with the same `assignment` carve-out.
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
