package test_oauth2_client_rotate_secret

import data.identity.oauth2.client.rotate_secret

test_allowed if {
	rotate_secret.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"oauth2_client": {"confidential": true}}}
	rotate_secret.allow with input as {"credentials": {"roles": [], "is_admin": true}, "existing": {"oauth2_client": {"confidential": true}}}
	rotate_secret.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"oauth2_client": {"domain_id": "foo", "confidential": true}}}
}

test_forbidden if {
	not rotate_secret.allow with input as {"credentials": {"roles": []}, "existing": {"oauth2_client": {"confidential": true}}}
	not rotate_secret.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"oauth2_client": {"domain_id": "foo1", "confidential": true}}}
	not rotate_secret.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"oauth2_client": {"domain_id": "foo", "confidential": true}}}
}

test_public_client_denied_even_for_admin if {
	not rotate_secret.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"oauth2_client": {"confidential": false}}}
	not rotate_secret.allow with input as {"credentials": {"roles": [], "is_admin": true}, "existing": {"oauth2_client": {"confidential": false}}}
}
