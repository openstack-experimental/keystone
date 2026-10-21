package test_oauth2_client_delete

import data.identity.oauth2.client.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}}
	delete.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"oauth2_client": {"domain_id": "foo"}}}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": []}}
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"oauth2_client": {"domain_id": "foo1"}}}
	not delete.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"oauth2_client": {"domain_id": "foo"}}}
}

test_dpop_bound_client_delete_by_manager_denied if {
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"oauth2_client": {"domain_id": "foo", "dpop_bound_access_tokens": true}}}
}

test_dpop_bound_client_delete_by_admin_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"oauth2_client": {"domain_id": "foo", "dpop_bound_access_tokens": true}}}
}
