# METADATA
# description: Core identity predicates and helper rules for Keystone4 policies
package common.identity

token_subject if {
	input.credentials.user_id == input.target.token.user.id
}

token_subject if {
	input.credentials.user_id == input.existing.token.user.id
}

# A role without a domain_id (orphaned).
# For create/update: in input.target.role.
# For show/delete: in input.existing.role.
orphaned_role if {
	input.target.role.domain_id == null
}

orphaned_role if {
	input.existing.role.domain_id == null
}

global_role if {
	orphaned_role
}

# A role with a domain matching the caller's domain scope.
# For create/update: in input.target.role.
# For show/delete: in input.existing.role.
own_role if {
	input.target.role.domain_id != null
	input.credentials.domain_id == input.target.role.domain_id
}

own_role if {
	input.existing.role.domain_id != null
	input.credentials.domain_id == input.existing.role.domain_id
}

# Domain role or the global role.
own_role_or_global_role if {
	global_role
}

own_role_or_global_role if {
	own_role
}

own_target if {
	count(_domain_ids) > 0
	every id in _domain_ids {
		id == input.credentials.domain_id
	}
}

foreign_target if {
	some id in _domain_ids
	id != input.credentials.domain_id
}

# Collect domain_id from any known wrapped resource key.
# Used by own_target / foreign_target / domain_matches_domain_scope.
# For create/list/update: resource is in input.target.
# For show/delete: resource is in input.existing.
_domain_ids contains input.target.instance.domain_id if {
	input.target.instance.domain_id != null
}

_domain_ids contains input.target.user.domain_id if {
	input.target.user.domain_id != null
}

_domain_ids contains input.target.group.domain_id if {
	input.target.group.domain_id != null
}

_domain_ids contains input.target.restriction.domain_id if {
	input.target.restriction.domain_id != null
}

_domain_ids contains input.target.project.domain_id if {
	input.target.project.domain_id != null
}

_domain_ids contains input.target.role.domain_id if {
	input.target.role.domain_id != null
}

_domain_ids contains input.target.token.domain_id if {
	input.target.token.domain_id != null
}

_domain_ids contains input.target.domain.id if {
	input.target.domain.id != null
}

_domain_ids contains input.target.scim_realm.domain_id if {
	input.target.scim_realm.domain_id != null
}

_domain_ids contains input.existing.instance.domain_id if {
	input.existing.instance.domain_id != null
}

_domain_ids contains input.existing.user.domain_id if {
	input.existing.user.domain_id != null
}

_domain_ids contains input.existing.group.domain_id if {
	input.existing.group.domain_id != null
}

_domain_ids contains input.existing.restriction.domain_id if {
	input.existing.restriction.domain_id != null
}

_domain_ids contains input.existing.project.domain_id if {
	input.existing.project.domain_id != null
}

_domain_ids contains input.existing.role.domain_id if {
	input.existing.role.domain_id != null
}

_domain_ids contains input.existing.token.domain_id if {
	input.existing.token.domain_id != null
}

_domain_ids contains input.existing.domain.id if {
	input.existing.domain.id != null
}

_domain_ids contains input.existing.scim_realm.domain_id if {
	input.existing.scim_realm.domain_id != null
}

_domain_ids contains input.target.scim_realm.domain_id if {
	input.target.scim_realm.domain_id != null
}

_domain_ids contains input.existing.user.domain_id if {
	input.existing.user.domain_id != null
}

_domain_ids contains input.target.user.domain_id if {
	input.target.user.domain_id != null
}

project_domain_matches_domain_scope if {
	input.target.project.domain_id != null
	input.target.project.domain_id = input.credentials.domain_id
}

project_domain_matches_domain_scope if {
	input.existing.project.domain_id != null
	input.existing.project.domain_id = input.credentials.domain_id
}

domain_matches_domain_scope if {
	count(_domain_ids) > 0
	every id in _domain_ids {
		id == input.credentials.domain_id
	}
}

# Both the group and the user of a group membership belong to the domain of the
# caller's domain scope. Used by the `identity/group/user/*` policies, where
# `input.existing` carries both `group` and `user` (`any_domain_id` cannot be
# used since it is only defined for a single resource).
membership_domains_match_domain_scope if {
	input.existing.group.domain_id != null
	input.existing.user.domain_id != null
	input.existing.group.domain_id == input.credentials.domain_id
	input.existing.user.domain_id == input.credentials.domain_id
}

is_system_admin if {
	"admin" in input.credentials.roles
	input.credentials.system == "all"
}

# Roles a domain manager is allowed to delegate (mirrors the Python Keystone
# `domain_managed_target_role` rule): only manager, member and reader.
# For grant/revoke the role is in input.target.role (or input.existing.role).
domain_managed_target_role if {
	input.target.role.name in {"manager", "member", "reader"}
}

domain_managed_target_role if {
	input.existing.role.name in {"manager", "member", "reader"}
}
