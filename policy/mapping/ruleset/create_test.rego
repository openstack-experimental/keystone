package test_mapping_ruleset_create

import data.identity.mapping.ruleset.create

test_allowed_admin if {
	create.allow with input as {"credentials": {"roles": ["admin"]}}
}

test_allowed_manager_own_domain if {
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d1", "domain_resolution_mode": {"type": "fixed"}}}}
}

test_forbidden_manager_claims_mode if {
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d1", "domain_resolution_mode": {"type": "claims_or_mapping"}}}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d1", "domain_resolution_mode": {"type": "claims_only"}}}}
}

test_forbidden_manager_foreign_domain if {
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d2"}}}
}

test_forbidden_manager_global if {
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"mapping": {"domain_resolution_mode": {"type": "fixed"}}}}
}

test_forbidden_manager_system_ruleset if {
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d1", "domain_resolution_mode": {"type": "fixed"}, "rules": [{"identity": {"is_system": true}}]}}}
}

test_forbidden_reader if {
	not create.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d1"}, "domain_resolution_mode": {"type": "fixed"}}}
}

test_violation_claims_mode if {
	create.violation with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d1", "domain_resolution_mode": {"type": "claims_or_mapping"}}}}
}

test_violation_foreign_domain if {
	create.violation with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d2"}}}
}
