package test_limit_list

import data.identity.limit.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"is_admin": true}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	list.allow with input as {"credentials": {"roles": ["member"], "project_id": "p1"}}
	list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "d1"}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["member"], "system": null, "project_id": null, "domain_id": null}}
}
