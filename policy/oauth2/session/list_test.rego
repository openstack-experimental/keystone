package test_oauth2_session_list

import data.identity.oauth2.session.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"domain_id": "foo"}}
	list.allow with input as {"credentials": {"roles": [], "is_admin": true}, "target": {"domain_id": "foo"}}
	list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain_id": "foo"}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}, "target": {"domain_id": "foo"}}
	not list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain_id": "bar"}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain_id": "foo"}}
}
