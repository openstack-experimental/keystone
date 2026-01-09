package test_auth_token_show

import data.identity.auth.token.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"roles": ["service"]}}
	show.allow with input as {"credentials": {"roles": ["reader"], "system_scope": "all"}}
	show.allow with input as {"credentials": {"user_id": "foo"}, "target": {"token": {"user_id": "foo"}}}
	show.allow with input as {"credentials": {"roles": ["admin"], "user_id": "foo"}, "target": {"token": {"user_id": "bar"}}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": ["reader"], "system_scope": "not_all"}}
	not show.allow with input as {"credentials": {"roles": ["manager"], "user_id": "foo"}, "target": {"token": {"user_id": "bar"}}}
	not show.allow with input as {"credentials": {"roles": ["member"], "user_id": "foo"}, "target": {"token": {"user_id": "bar"}}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "user_id": "foo"}, "target": {"token": {"user_id": "bar"}}}
}
