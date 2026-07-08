package test_scim_realm_create

import data.identity.scim_realm.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}}
	create.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"scim_realm": {"domain_id": "foo"}}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"scim_realm": {"domain_id": "foo1"}}}
	not create.allow with input as {"credentials": {"roles": ["manager"]}, "target": {"scim_realm": {"domain_id": "foo"}}}
	not create.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"scim_realm": {"domain_id": "foo"}}}
}
