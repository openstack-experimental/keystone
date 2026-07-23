package test_trust_delete

import data.identity.trust.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"trust": {"trustor_user_id": "other", "trustee_user_id": "other2"}}}
	delete.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"trust": {"trustor_user_id": "u1", "trustee_user_id": "other"}}}
}

test_forbidden if {
	# The trustee has no authority to revoke a trust it did not grant.
	not delete.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"trust": {"trustor_user_id": "other", "trustee_user_id": "u1"}}}

	not delete.allow with input as {"credentials": {"roles": []}, "existing": {"trust": {"trustor_user_id": "u1", "trustee_user_id": "other"}}}
}
