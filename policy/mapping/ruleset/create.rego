# METADATA
# description: Policy for creating mapping rulesets
package identity.mapping.ruleset.create

import data.identity.mapping as mapping_common

# Create MappingRuleSet (MappingRuleSetCreate).
#
# input.target.mapping fields:
#   mapping_id:               string (optional)
#   domain_id:                string (optional)  -- null == global
#   source:                   object       IdentitySource { type, idp_id/cluster_id/trust_domain }
#   domain_resolution_mode:   object       { type: "fixed" | "claims_or_mapping" | "claims_only", allowed_domains }
#   enabled:                  boolean
#   rules:                    array        of MappingRule
#
# input.existing is null.
#
# Rules:
# - Only admin can create rulesets with domain_id unset (global).
# - Domain manager can create rulesets with domain_id matching their scope.
# - is_system requires admin.
# - claims_mode_resolution requires admin.

default allow := false

allow if {
	not mapping_common.global_ruleset
	mapping_common.own_ruleset
	not mapping_common.is_system_ruleset
	not mapping_common.claims_mode_resolution
	"manager" in input.credentials.roles
}

allow if {
	"admin" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": msg} if {
	mapping_common.global_ruleset
	not "admin" in input.credentials.roles
	msg := "creating a global mapping ruleset requires `admin` role."
}

violation contains {"field": "domain_id", "msg": msg} if {
	mapping_common.foreign_ruleset
	not "admin" in input.credentials.roles
	msg := "creating a mapping ruleset for another domain requires `admin` role."
}

violation contains {"field": "is_system", "msg": msg} if {
	mapping_common.is_system_ruleset
	not "admin" in input.credentials.roles
	msg := "creating a system mapping ruleset requires `admin` role."
}

violation contains {"field": "domain_resolution_mode", "msg": msg} if {
	mapping_common.claims_mode_resolution
	not "admin" in input.credentials.roles
	msg := "claims-based domain resolution mode requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	mapping_common.own_ruleset
	not mapping_common.is_system_ruleset
	not mapping_common.claims_mode_resolution
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "creating a mapping ruleset requires `manager` role."
}
