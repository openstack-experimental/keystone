package test_oauth2_client_show

import data.identity.oauth2.client.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"oauth2_client": {"domain_id": "foo"}}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"oauth2_client": {"domain_id": "foo1"}}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"oauth2_client": {"domain_id": "foo"}}}
}
