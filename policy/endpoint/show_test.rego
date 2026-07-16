package test_endpoint_show

import data.identity.endpoint.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"is_admin": true}}
	show.allow with input as {"credentials": {"roles": ["reader"], "system_scope": "all"}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["reader"]}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "system_scope": "domain"}}
	not show.allow with input as {"credentials": {"roles": ["manager"]}}
}
