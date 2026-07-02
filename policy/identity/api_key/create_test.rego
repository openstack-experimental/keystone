package test_api_key_create

import data.identity.api_key.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}}
	create.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"api_key": {"domain_id": "foo"}}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"api_key": {"domain_id": "foo1"}}}
	not create.allow with input as {"credentials": {"roles": ["manager"]}, "target": {"api_key": {"domain_id": "foo"}}}
	not create.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"api_key": {"domain_id": "foo"}}}
}
