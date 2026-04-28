package test_role_list

import data.identity.role.list

test_allowed if {
	#list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain_a"}, "target": {"domain_id": "domain_a"}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain_a"}, "target": {"domain_id": "domain_b"}}
	not list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain_a"}, "target": {"domain_id": "domain_b"}}
}
