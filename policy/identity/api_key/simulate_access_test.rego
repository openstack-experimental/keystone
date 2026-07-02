package test_api_key_simulate_access

import data.identity.api_key.simulate_access

test_allowed if {
	simulate_access.allow with input as {"credentials": {"roles": ["admin"]}}
	simulate_access.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	simulate_access.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"api_key": {"domain_id": "foo"}}}
}

test_forbidden if {
	not simulate_access.allow with input as {"credentials": {"roles": []}}
	not simulate_access.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"api_key": {"domain_id": "foo1"}}}
	not simulate_access.allow with input as {"credentials": {"roles": ["manager"]}, "existing": {"api_key": {"domain_id": "foo"}}}
	not simulate_access.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"api_key": {"domain_id": "foo"}}}
}
