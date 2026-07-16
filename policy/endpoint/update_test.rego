package test_endpoint_update

import data.identity.endpoint.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"endpoint": {"enabled": false}}}
	update.allow with input as {"credentials": {"is_admin": true}, "target": {"endpoint": {"enabled": false}}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["reader"]}, "target": {"endpoint": {"enabled": false}}}
	not update.allow with input as {"credentials": {"roles": ["manager"]}, "target": {"endpoint": {"enabled": false}}}
}
