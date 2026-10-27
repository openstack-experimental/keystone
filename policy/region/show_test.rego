package test_region_show

import data.identity.region.show

test_allowed_with_valid_token if {
	show.allow with input as {"credentials": {"user_id": "uid", "roles": []}}
	show.allow with input as {"credentials": {"user_id": "uid", "roles": ["manager"]}}
	show.allow with input as {"credentials": {"user_id": "uid", "roles": ["reader"], "system": "domain"}}
}

test_forbidden_without_user if {
	not show.allow with input as {"credentials": {"user_id": "", "roles": ["admin"]}}
	not show.allow with input as {"credentials": {"roles": ["admin"]}}
	not show.allow with input as {"credentials": {}}
}
