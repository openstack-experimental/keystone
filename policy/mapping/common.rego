# METADATA
# description: Shared predicates for mapping ruleset policies
package identity.mapping

import data.identity

# Resolve domain_id from target or existing depending on operation.
# Create/List: domain_id is in input.target.mapping.
# Update/Show/Delete: domain_id is in input.existing.mapping.
ruleset_domain_id := input.target.mapping.domain_id if {
	input.target.mapping.domain_id
}

ruleset_domain_id := input.existing.mapping.domain_id if {
	input.existing.mapping.domain_id
}

own_ruleset if {
	ruleset_domain_id != null
	ruleset_domain_id == input.credentials.domain_id
}

foreign_ruleset if {
	ruleset_domain_id != null
	ruleset_domain_id != input.credentials.domain_id
}

global_ruleset if {
	ruleset_domain_id == null
}

# Any rule has is_system: true -> system mapping (immutable for update/delete).
# Checked against both target and existing to cover all operations.
is_system_ruleset if {
	input.existing.mapping.rules[_].identity.is_system == true
}

is_system_ruleset if {
	input.target.mapping.rules[_].identity.is_system == true
}

# DomainResolutionMode requires admin for non-Fixed variants.
# Serialized with tag "type": "fixed", "claims_or_mapping", "claims_only".
claims_mode_resolution if {
	mode := input.target.mapping.domain_resolution_mode
	mode.type == "claims_or_mapping"
}

claims_mode_resolution if {
	mode := input.target.mapping.domain_resolution_mode
	mode.type == "claims_only"
}
