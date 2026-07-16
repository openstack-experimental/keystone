package test_service_create

import data.identity.service.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"service": {"enabled": true}}}
	create.allow with input as {"credentials": {"is_admin": true}, "target": {"service": {"enabled": true}}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["reader"]}, "target": {"service": {"enabled": true}}}
	not create.allow with input as {"credentials": {"roles": ["manager"]}, "target": {"service": {"enabled": true}}}
}
