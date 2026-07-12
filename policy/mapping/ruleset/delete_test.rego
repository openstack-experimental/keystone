package test_mapping_ruleset_delete

import data.identity.mapping.ruleset.delete

test_allowed_admin if {
	delete.allow with input as {"credentials": {"roles": ["admin"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d2", "rules": []}}}
}

test_allowed_is_admin if {
	delete.allow with input as {"credentials": {"is_admin": true}, "existing": {"mapping": {"domain_id": "d2", "rules": []}}}
}

test_allowed_manager_own if {
	delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d1", "rules": []}}}
}

test_forbidden_manager_foreign if {
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d2", "rules": []}}}
}

test_forbidden_reader if {
	not delete.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d1", "rules": []}}}
}

test_violation_foreign_domain if {
	delete.violation with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d2", "rules": []}}}
}
