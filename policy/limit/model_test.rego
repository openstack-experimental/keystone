package test_limit_model

import data.identity.limit.model

test_allowed if {
	model.allow with input as {"credentials": {"roles": ["admin"]}}
	model.allow with input as {"credentials": {"is_admin": true}}
	model.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	model.allow with input as {"credentials": {"roles": ["member"], "project_id": "p1"}}
	model.allow with input as {"credentials": {"roles": ["member"], "domain_id": "d1"}}
}

test_forbidden if {
	not model.allow with input as {"credentials": {"roles": []}}
	not model.allow with input as {"credentials": {"roles": ["member"], "system": null, "project_id": null, "domain_id": null}}
}
