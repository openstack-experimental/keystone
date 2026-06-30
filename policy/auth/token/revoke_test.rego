package test_auth_token_revoke

import data.identity.auth.token.revoke

test_allowed if {
	revoke.allow with input as {"credentials": {"roles": ["admin"]}}
	revoke.allow with input as {"credentials": {"user_id": "foo"}, "existing": {"token": {"user_id": "foo"}}}
}

test_forbidden if {
	not revoke.allow with input as {"credentials": {"roles": ["reader"], "system_scope": "not_all"}}
	not revoke.allow with input as {"credentials": {"roles": ["manager"], "user_id": "foo"}, "existing": {"token": {"user_id": "bar"}}}
	not revoke.allow with input as {"credentials": {"roles": ["member"], "user_id": "foo"}, "existing": {"token": {"user_id": "bar"}}}
	not revoke.allow with input as {"credentials": {"roles": ["reader"], "user_id": "foo"}, "existing": {"token": {"user_id": "bar"}}}
}
