package test_endpoint_delete

import data.identity.endpoint.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}}
	delete.allow with input as {"credentials": {"is_admin": true}}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": []}}
	not delete.allow with input as {"credentials": {"roles": ["reader"]}}
	not delete.allow with input as {"credentials": {"roles": ["manager"]}}
}
