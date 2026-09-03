package test_domain_config_create

import data.identity.domain_config.create

test_admin_allowed if {
	create.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	create.allow with input as {"credentials": {"roles": ["admin"], "is_admin": true}}
}

test_domain_manager_allowed if {
	create.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d1"},
	}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not create.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d2"},
	}
	not create.allow with input as {"credentials": {"roles": []}}
}
