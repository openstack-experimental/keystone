package test_oauth2_client_create

import data.identity.oauth2.client.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}}
	create.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain_id": "foo", "oauth2_client": {"pre_authorized": false}}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain_id": "foo1", "oauth2_client": {"pre_authorized": false}}}
	not create.allow with input as {"credentials": {"roles": []}, "target": {"domain_id": "foo"}}
	not create.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain_id": "foo", "oauth2_client": {"pre_authorized": false}}}
}

test_pre_authorized_by_manager_denied if {
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain_id": "foo", "oauth2_client": {"pre_authorized": true}}}
}

test_pre_authorized_by_admin_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"domain_id": "foo", "oauth2_client": {"pre_authorized": true}}}
}
