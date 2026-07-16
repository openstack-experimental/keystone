package test_oauth2_key_list_local_emergency_candidates

import data.identity.oauth2.key.list_local_emergency_candidates

test_allowed if {
	list_local_emergency_candidates.allow with input as {"credentials": {"roles": ["admin"]}}
	list_local_emergency_candidates.allow with input as {"credentials": {"roles": [], "is_admin": true}}
}

test_forbidden if {
	not list_local_emergency_candidates.allow with input as {"credentials": {"roles": []}}
	not list_local_emergency_candidates.allow with input as {"credentials": {"roles": ["manager"]}}
}
