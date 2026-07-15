package test_oauth2_key_confirm_rotate_signing_key

import data.identity.oauth2.key.confirm_rotate_signing_key

test_allowed if {
	confirm_rotate_signing_key.allow with input as {"credentials": {"roles": ["admin"]}}
	confirm_rotate_signing_key.allow with input as {"credentials": {"roles": [], "is_admin": true}}
}

test_forbidden if {
	not confirm_rotate_signing_key.allow with input as {"credentials": {"roles": []}}
	not confirm_rotate_signing_key.allow with input as {"credentials": {"roles": ["manager"]}}
}
