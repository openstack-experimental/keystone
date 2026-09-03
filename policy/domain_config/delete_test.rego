package test_domain_config_delete

import data.identity.domain_config.delete

test_admin_allowed if {
	delete.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	delete.allow with input as {"credentials": {"roles": ["admin"], "is_admin": true}}
}

test_domain_manager_allowed if {
	delete.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d1"},
	}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not delete.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d2"},
	}
	not delete.allow with input as {"credentials": {"roles": []}}
}
