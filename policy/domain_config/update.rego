# METADATA
# description: Policy for merging changes into a domain's configuration
package identity.domain_config.update

# Update (PATCH) the whole configuration of a domain, a single group or a
# single option.
#
# `input.target.domain_id` is the domain being configured.
# `input.target.group`  (optional) is the addressed group.
# `input.target.option` (optional) is the addressed option.
# `input.target.config` (whole/group only) is the request body with sensitive
#   options stripped.
# `input.existing` is null.

default allow := false

# The configured admin SVID (system-level operator) may write any group.
allow if {
	input.credentials.is_admin
}

# A system-scoped `admin` — a cloud administrator — may write any group,
# including `assignment` (ADR 0034 §6).
allow if {
	"admin" in input.credentials.roles
	input.credentials.system == "all"
}

# An `admin` on any other scope may write any group EXCEPT `assignment`:
# binding a domain to an assignment backend is a role-minting surface reserved
# for cloud admins, and must not be satisfiable by a domain- or project-scoped
# token (ADR 0034 §6).
allow if {
	"admin" in input.credentials.roles
	not touches_assignment_group
}

# A domain manager may configure the domain their token is scoped to, with the
# same `assignment` carve-out.
allow if {
	"manager" in input.credentials.roles
	input.credentials.domain_id == input.target.domain_id
	not touches_assignment_group
}

# The write addresses the `assignment` group directly (group or option path).
touches_assignment_group if {
	input.target.group == "assignment"
}

# ...or carries an `assignment` block in a whole-config PATCH/PUT body.
touches_assignment_group if {
	input.target.config.assignment
}

violation contains {"field": "", "msg": "writing a domain configuration requires system admin or the `manager` role on the domain."} if {
	not allow
}
