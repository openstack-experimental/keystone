package test_endpoint_create

import data.identity.endpoint.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"endpoint": {"enabled": true}}}
	create.allow with input as {"credentials": {"is_admin": true}, "target": {"endpoint": {"enabled": true}}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["reader"]}, "target": {"endpoint": {"enabled": true}}}
	not create.allow with input as {"credentials": {"roles": ["manager"]}, "target": {"endpoint": {"enabled": true}}}
}
