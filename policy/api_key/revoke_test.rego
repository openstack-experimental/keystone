package test_api_key_revoke

import data.identity.api_key.revoke

test_allowed if {
	revoke.allow with input as {"credentials": {"roles": ["admin"]}}
	revoke.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"api_key": {"domain_id": "foo"}}}
}

test_forbidden if {
	not revoke.allow with input as {"credentials": {"roles": []}}
	not revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"api_key": {"domain_id": "foo1"}}}
	not revoke.allow with input as {"credentials": {"roles": ["manager"]}, "existing": {"api_key": {"domain_id": "foo"}}}
	not revoke.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"api_key": {"domain_id": "foo"}}}
}
