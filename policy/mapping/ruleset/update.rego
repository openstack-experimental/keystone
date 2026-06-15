# METADATA
# description: Policy for updating mapping rulesets and mutating rules
package identity.mapping.ruleset.update

import data.identity.mapping as mapping_common

# Update MappingRuleSet (PUT) via MappingRuleSetUpdate, or mutate rules
# (POST /v4/mappings/{mapping_id}/rules/mutate) via RuleMutations.
# Shared policy: identity/mapping/ruleset/update
#
# input.target.mapping: MappingRuleSetUpdate / RuleMutations payload
# input.existing.mapping: stored MappingRuleSet object

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	mapping_common.own_ruleset
	"manager" in input.credentials.roles
	not mapping_common.is_system_ruleset
}

violation contains {"field": "is_system", "msg": msg} if {
	mapping_common.is_system_ruleset
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "updating system mapping ruleset requires `admin` role."
}

violation contains {"field": "domain_id", "msg": msg} if {
	mapping_common.foreign_ruleset
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "updating mapping ruleset for other domain requires `admin` role."
}

violation contains {"field": "domain_id", "msg": msg} if {
	mapping_common.global_ruleset
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "updating global mapping ruleset requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	mapping_common.own_ruleset
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "updating mapping ruleset requires `manager` role."
}
