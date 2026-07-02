package test_api_key_show

import data.identity.api_key.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"api_key": {"domain_id": "foo"}}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"api_key": {"domain_id": "foo1"}}}
	not show.allow with input as {"credentials": {"roles": ["manager"]}, "existing": {"api_key": {"domain_id": "foo"}}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"api_key": {"domain_id": "foo"}}}
}
