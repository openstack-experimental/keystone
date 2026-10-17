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

test_delegation_by_manager_denied if {
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"oauth2_client": {"delegation": {"service_grants": true}}}, "existing": {"oauth2_client": {"domain_id": "foo"}}}
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"oauth2_client": {"spiffe_ids": ["spiffe://td/x"]}}, "existing": {"oauth2_client": {"domain_id": "foo"}}}
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"oauth2_client": {"remove_delegation": true}}, "existing": {"oauth2_client": {"domain_id": "foo"}}}
}

test_existing_delegation_edit_by_manager_denied if {
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"oauth2_client": {"enabled": false}}, "existing": {"oauth2_client": {"domain_id": "foo", "spiffe_ids": ["spiffe://td/x"], "delegation": {"service_grants": true}}}}
}

test_manager_edit_without_delegation_allowed if {
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"oauth2_client": {"enabled": false, "delegation": null, "spiffe_ids": null, "remove_delegation": false}}, "existing": {"oauth2_client": {"domain_id": "foo", "spiffe_ids": [], "delegation": null}}}
}

test_delegation_by_admin_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"oauth2_client": {"delegation": {"service_grants": true}}}, "existing": {"oauth2_client": {"domain_id": "foo"}}}
}
