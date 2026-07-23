package test_region_create

import data.identity.region.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"region": {}}}
	create.allow with input as {"credentials": {"is_admin": true}, "target": {"region": {}}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["reader"]}, "target": {"region": {}}}
	not create.allow with input as {"credentials": {"roles": ["manager"]}, "target": {"region": {}}}
}
