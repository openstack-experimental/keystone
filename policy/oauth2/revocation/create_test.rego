package test_oauth2_revocation_create

import data.identity.oauth2.revocation.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"domain_id": "foo"}}
	create.allow with input as {"credentials": {"roles": [], "is_admin": true}, "target": {"domain_id": "foo"}}
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain_id": "foo"}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}, "target": {"domain_id": "foo"}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain_id": "bar"}}
	not create.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain_id": "foo"}}
}
