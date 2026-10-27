package test_region_list

import data.identity.region.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"is_admin": true}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	list.allow with input as {"credentials": {"roles": []}}
	list.allow with input as {"credentials": {"roles": ["reader"]}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "domain"}}
	list.allow with input as {"credentials": {"roles": ["manager"]}}
}
