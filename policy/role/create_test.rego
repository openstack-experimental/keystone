package test_role_create

import data.identity.role.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"], "domain_id": "domain_a"}, "target": {"domain_id": "domain_a"}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain_a"}, "target": {"domain_id": "domain_a"}}
}
