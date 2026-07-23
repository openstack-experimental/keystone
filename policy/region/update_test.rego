package test_region_update

import data.identity.region.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"region": {"description": "updated"}}}
	update.allow with input as {"credentials": {"is_admin": true}, "target": {"region": {"description": "updated"}}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["reader"]}, "target": {"region": {"description": "updated"}}}
	not update.allow with input as {"credentials": {"roles": ["manager"]}, "target": {"region": {"description": "updated"}}}
}
