package test_region_list

import data.identity.region.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"is_admin": true}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system_scope": "all"}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["reader"]}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "system_scope": "domain"}}
	not list.allow with input as {"credentials": {"roles": ["manager"]}}
}
