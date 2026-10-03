package test_limit_create

import data.identity.limit.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}}
	create.allow with input as {"credentials": {"is_admin": true}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "project_id": "p1"}}
	not create.allow with input as {"credentials": {"roles": ["member"], "domain_id": "d1"}}
}
