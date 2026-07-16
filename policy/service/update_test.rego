package test_service_update

import data.identity.service.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"service": {"enabled": false}}}
	update.allow with input as {"credentials": {"is_admin": true}, "target": {"service": {"enabled": false}}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["reader"]}, "target": {"service": {"enabled": false}}}
	not update.allow with input as {"credentials": {"roles": ["manager"]}, "target": {"service": {"enabled": false}}}
}
