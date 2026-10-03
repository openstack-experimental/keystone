package test_registered_limit_delete

import data.identity.registered_limit.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}}
	delete.allow with input as {"credentials": {"is_admin": true}}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": []}}
	not delete.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not delete.allow with input as {"credentials": {"roles": ["manager"], "project_id": "p1"}}
	not delete.allow with input as {"credentials": {"roles": ["member"], "domain_id": "d1"}}
}
