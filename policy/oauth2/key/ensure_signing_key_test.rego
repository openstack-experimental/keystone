package test_oauth2_key_ensure_signing_key

import data.identity.oauth2.key.ensure_signing_key

test_allowed if {
	ensure_signing_key.allow with input as {"credentials": {"roles": ["admin"]}}
	ensure_signing_key.allow with input as {"credentials": {"roles": [], "is_admin": true}}
}

test_forbidden if {
	not ensure_signing_key.allow with input as {"credentials": {"roles": []}}
	not ensure_signing_key.allow with input as {"credentials": {"roles": ["manager"]}}
	not ensure_signing_key.allow with input as {"credentials": {"roles": ["reader"]}}
}
