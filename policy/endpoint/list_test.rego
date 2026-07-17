package test_endpoint_list

import data.identity.endpoint.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"is_admin": true}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["reader"]}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "system": "domain"}}
	not list.allow with input as {"credentials": {"roles": ["manager"]}}
}
