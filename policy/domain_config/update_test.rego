package test_domain_config_update

import data.identity.domain_config.update

test_admin_allowed if {
	update.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	update.allow with input as {"credentials": {"roles": ["admin"], "is_admin": true}}
}

test_domain_manager_allowed if {
	update.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d1"},
	}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not update.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d2"},
	}
	not update.allow with input as {"credentials": {"roles": []}}
}
