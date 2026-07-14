package test_oauth2_client_update

import data.identity.oauth2.client.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}}
	update.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"oauth2_client": {"enabled": false}}, "existing": {"oauth2_client": {"domain_id": "foo"}}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"oauth2_client": {}}, "existing": {"oauth2_client": {"domain_id": "foo1"}}}
	not update.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"oauth2_client": {}}, "existing": {"oauth2_client": {"domain_id": "foo"}}}
}

test_pre_authorized_by_manager_denied if {
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"oauth2_client": {"pre_authorized": true}}, "existing": {"oauth2_client": {"domain_id": "foo"}}}
}

test_pre_authorized_by_admin_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"oauth2_client": {"pre_authorized": true}}, "existing": {"oauth2_client": {"domain_id": "foo"}}}
}

test_existing_pre_authorized_edit_by_manager_denied if {
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"oauth2_client": {"enabled": false}}, "existing": {"oauth2_client": {"domain_id": "foo", "pre_authorized": true}}}
}

test_existing_pre_authorized_edit_by_admin_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"oauth2_client": {"enabled": false}}, "existing": {"oauth2_client": {"domain_id": "foo", "pre_authorized": true}}}
}
