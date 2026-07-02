package test_api_key_update

import data.identity.api_key.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}}
	update.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"api_key": {"domain_id": "foo"}}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"api_key": {"domain_id": "foo1"}}}
	not update.allow with input as {"credentials": {"roles": ["manager"]}, "existing": {"api_key": {"domain_id": "foo"}}}
	not update.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"api_key": {"domain_id": "foo"}}}
}
