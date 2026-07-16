package test_oauth2_key_reconcile_local_emergency_key

import data.identity.oauth2.key.reconcile_local_emergency_key

test_allowed if {
	reconcile_local_emergency_key.allow with input as {"credentials": {"roles": ["admin"]}}
	reconcile_local_emergency_key.allow with input as {"credentials": {"roles": [], "is_admin": true}}
}

test_forbidden if {
	not reconcile_local_emergency_key.allow with input as {"credentials": {"roles": []}}
	not reconcile_local_emergency_key.allow with input as {"credentials": {"roles": ["manager"]}}
}
