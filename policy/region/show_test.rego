package test_region_show

import data.identity.region.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"is_admin": true}}
	show.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	show.allow with input as {"credentials": {"roles": []}}
	show.allow with input as {"credentials": {"roles": ["reader"]}}
	show.allow with input as {"credentials": {"roles": ["reader"], "system": "domain"}}
	show.allow with input as {"credentials": {"roles": ["manager"]}}
}
