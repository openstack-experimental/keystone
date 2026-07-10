package test_mapping_ruleset_update

import data.identity.mapping.ruleset.update

test_allowed_admin if {
	update.allow with input as {"credentials": {"roles": ["admin"]}}
}

test_allowed_is_admin if {
	update.allow with input as {"credentials": {"is_admin": true}}
}

test_allowed_manager_own if {
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d1", "rules": []}}}
}

test_forbidden_manager_system_ruleset if {
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d1", "rules": [{"identity": {"is_system": true}}]}}}
}

test_forbidden_manager_foreign if {
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d2", "rules": []}}}
}

test_forbidden_reader if {
	not update.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d1", "rules": []}}}
}

test_violation_system_ruleset if {
	update.violation with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d1", "rules": [{"identity": {"is_system": true}}]}}}
}
