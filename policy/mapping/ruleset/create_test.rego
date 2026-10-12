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

test_allowed_manager_own_domain_scopes if {
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d1", "domain_resolution_mode": {"type": "fixed"}, "rules": [{"authorizations": [{"type": "domain", "domain_id": "d1"}, {"type": "project", "project_id": "p1", "project_domain_id": "d1"}]}]}}}
}

test_forbidden_manager_system_authorization if {
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d1", "domain_resolution_mode": {"type": "fixed"}, "rules": [{"authorizations": [{"type": "system", "system_id": "all"}]}]}}}
	create.violation with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d1", "domain_resolution_mode": {"type": "fixed"}, "rules": [{"authorizations": [{"type": "system", "system_id": "all"}]}]}}}
}

test_forbidden_manager_foreign_domain_authorization if {
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d1", "domain_resolution_mode": {"type": "fixed"}, "rules": [{"authorizations": [{"type": "domain", "domain_id": "d2"}]}]}}}
}

test_forbidden_manager_foreign_project_authorization if {
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d1", "domain_resolution_mode": {"type": "fixed"}, "rules": [{"authorizations": [{"type": "project", "project_id": "p2", "project_domain_id": "d2"}]}]}}}
}

test_allowed_admin_system_authorization if {
	create.allow with input as {"credentials": {"roles": ["admin"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d1", "rules": [{"authorizations": [{"type": "system", "system_id": "all"}]}]}}}
}
