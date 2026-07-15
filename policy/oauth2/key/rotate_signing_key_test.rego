package test_oauth2_key_rotate_signing_key

import data.identity.oauth2.key.rotate_signing_key

test_allowed if {
	rotate_signing_key.allow with input as {"credentials": {"roles": ["admin"]}}
	rotate_signing_key.allow with input as {"credentials": {"roles": [], "is_admin": true}}
}

test_forbidden if {
	not rotate_signing_key.allow with input as {"credentials": {"roles": []}}
	not rotate_signing_key.allow with input as {"credentials": {"roles": ["manager"]}}
	not rotate_signing_key.allow with input as {"credentials": {"roles": ["reader"]}}
}
