package test_domain_config_show

import data.identity.domain_config.show

test_admin_allowed if {
	show.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	show.allow with input as {"credentials": {"roles": ["admin"], "is_admin": true}}
}

test_system_reader_allowed if {
	show.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
}

test_domain_manager_allowed if {
	show.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d1"},
	}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "d1"}}
	not show.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d2"},
	}
	not show.allow with input as {"credentials": {"roles": []}}
}
