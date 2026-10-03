package test_registered_limit_show

import data.identity.registered_limit.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"is_admin": true}}
	show.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	show.allow with input as {"credentials": {"roles": ["member"], "project_id": "p1"}}
	show.allow with input as {"credentials": {"roles": ["member"], "domain_id": "d1"}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["reader"]}}
	not show.allow with input as {"credentials": {"roles": ["member"], "system": null, "project_id": null, "domain_id": null}}
}
