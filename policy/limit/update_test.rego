package test_limit_update

import data.identity.limit.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}}
	update.allow with input as {"credentials": {"is_admin": true}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not update.allow with input as {"credentials": {"roles": ["manager"], "project_id": "p1"}}
	not update.allow with input as {"credentials": {"roles": ["member"], "domain_id": "d1"}}
}
