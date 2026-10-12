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

test_allowed_manager_own_domain_scope if {
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d1", "rules": []}}, "target": {"mapping": {"rules": [{"authorizations": [{"type": "domain", "domain_id": "d1"}]}]}}}
}

test_forbidden_manager_system_authorization if {
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d1", "rules": []}}, "target": {"mapping": {"rules": [{"authorizations": [{"type": "system", "system_id": "all"}]}]}}}
	update.violation with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d1", "rules": []}}, "target": {"mapping": {"rules": [{"authorizations": [{"type": "system", "system_id": "all"}]}]}}}
}

test_forbidden_manager_foreign_project_authorization if {
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d1", "rules": []}}, "target": {"mapping": {"rules": [{"authorizations": [{"type": "project", "project_id": "p2", "project_domain_id": "d2"}]}]}}}
}

test_forbidden_manager_mutation_foreign_domain_authorization if {
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d1", "rules": []}}, "target": {"mapping": {"mutations": [{"operation": "insert", "rule": {"authorizations": [{"type": "domain", "domain_id": "d2"}]}}]}}}
}

test_allowed_admin_mutation_system_authorization if {
	update.allow with input as {"credentials": {"roles": ["admin"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d1", "rules": []}}, "target": {"mapping": {"mutations": [{"operation": "insert", "rule": {"authorizations": [{"type": "system", "system_id": "all"}]}}]}}}
}
