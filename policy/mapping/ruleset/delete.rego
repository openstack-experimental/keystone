# METADATA
# description: Policy for deleting mapping rulesets
package identity.mapping.ruleset.delete

import data.identity.mapping as mapping_common

# Delete MappingRuleSet.
#
# The `input.target` is null.
#
# The `input.existing.mapping` is the stored MappingRuleSet object:
#   mapping_id:               string               The ruleset ID.
#   domain_id:                string | null        Domain (null means global).
#   enabled:                  boolean              Enabled state.
#   rules:                    array                Mapping rules. Each rule may
#                                                  have identity.is_system.
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
}

violation contains {"field": "domain_id", "msg": msg} if {
	mapping_common.foreign_ruleset
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "deleting mapping ruleset for other domain requires `admin` role."
}

violation contains {"field": "domain_id", "msg": msg} if {
	mapping_common.global_ruleset
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "deleting global mapping ruleset requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	mapping_common.own_ruleset
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	msg := "deleting mapping ruleset requires `manager` role."
}
