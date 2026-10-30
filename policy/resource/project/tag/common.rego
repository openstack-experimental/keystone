# METADATA
# title: Project tag policy helpers
# description: >
#   Shared predicates for the project tag read policies
#   (identity.resource.project.tag.list and .show).
package identity.resource.project.tag

# METADATA
# description: >
#   True when the caller holds a project scoped token for the target project
#   (`input.existing.project.id`). A delegated caller (trust, application
#   credential) must additionally match the delegation's own immutable
#   project, with the token scope pinned to it as a scope-drift tripwire.
is_own_project if {
	caller_not_delegated
	input.credentials.project_id != null
	input.credentials.project_id == input.existing.project.id
}

is_own_project if {
	caller_delegated
	input.credentials.delegated_project_id != null
	input.credentials.project_id == input.credentials.delegated_project_id
	input.existing.project.id == input.credentials.delegated_project_id
}

# True when the caller authenticated directly (no trust or application
# credential in the authentication chain).
caller_not_delegated if {
	not input.credentials.is_delegated
}

caller_delegated if {
	input.credentials.is_delegated
}
