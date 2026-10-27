package test_region_list

import data.identity.region.list

test_allowed_with_valid_token if {
	list.allow with input as {"credentials": {"user_id": "uid", "roles": []}}
	list.allow with input as {"credentials": {"user_id": "uid", "roles": ["manager"]}}
	list.allow with input as {"credentials": {"user_id": "uid", "roles": ["reader"], "system": "domain"}}
}

test_forbidden_without_user if {
	not list.allow with input as {"credentials": {"user_id": "", "roles": ["admin"]}}
	not list.allow with input as {"credentials": {"roles": ["admin"]}}
	not list.allow with input as {"credentials": {}}
}
