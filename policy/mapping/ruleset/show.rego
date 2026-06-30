# METADATA
# description: Policy for viewing mapping ruleset details
package identity.mapping.ruleset.show

import data.identity.mapping as mapping_common

# Show MappingRuleSet.
#
# input.existing.mapping is the stored MappingRuleSet object.
# input.target is null.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	mapping_common.own_ruleset
	"reader" in input.credentials.roles
}

allow if {
	mapping_common.global_ruleset
	"reader" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": msg} if {
	mapping_common.foreign_ruleset
	not "admin" in input.credentials.roles
	not input.credentials.is_admin
	msg := "showing mapping ruleset for other domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	mapping_common.own_ruleset
	not "admin" in input.credentials.roles
	not "reader" in input.credentials.roles
	msg := "showing own mapping ruleset requires `reader` role."
}

violation contains {"field": "role", "msg": msg} if {
	mapping_common.global_ruleset
	not "admin" in input.credentials.roles
	not "reader" in input.credentials.roles
	msg := "showing global mapping ruleset requires `reader` role."
}
