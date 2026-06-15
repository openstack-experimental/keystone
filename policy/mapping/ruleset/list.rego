# METADATA
# description: Policy for listing mapping rulesets
package identity.mapping.ruleset.list

import data.identity.mapping as mapping_common

# List MappingRuleSets.
#
# input.target.mapping is the query parameters (MappingRuleSetListParameters):
#   domain_id:    string (optional)
#   enabled:      boolean (optional)
#   limit:        number (optional)
#   marker:       string (optional)
#
# input.existing is null.
# can_see_other_domain_resources indicates to the handler whether the caller
# is allowed to query rulesets belonging to other domains.

default allow := false

default can_see_other_domain_resources := false

can_see_other_domain_resources if {
	"admin" in input.credentials.roles
	true
}

can_see_other_domain_resources if {
	input.credentials.is_admin
	true
}

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
	msg := "listing mapping rulesets for other domain requires `admin` role."
}

violation contains {"field": "role", "msg": msg} if {
	mapping_common.own_ruleset
	not "admin" in input.credentials.roles
	not "reader" in input.credentials.roles
	msg := "listing own mapping rulesets requires `reader` role."
}

violation contains {"field": "role", "msg": msg} if {
	mapping_common.global_ruleset
	not "admin" in input.credentials.roles
	not "reader" in input.credentials.roles
	msg := "listing global mapping rulesets requires `reader` role."
}
