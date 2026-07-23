package test_trust_show

import data.identity.trust.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"trust": {"trustor_user_id": "other", "trustee_user_id": "other2"}}}
	show.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}, "existing": {"trust": {"trustor_user_id": "other", "trustee_user_id": "other2"}}}
	show.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"trust": {"trustor_user_id": "u1", "trustee_user_id": "other"}}}
	show.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"trust": {"trustor_user_id": "other", "trustee_user_id": "u1"}}}
}

test_forbidden if {
	# Neither trustor nor trustee, no elevated role.
	not show.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"trust": {"trustor_user_id": "other", "trustee_user_id": "other2"}}}
}
