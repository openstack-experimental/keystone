package test_user_update

import data.identity.user.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}}
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"user": {"domain_id": "foo"}}, "target": {"user": {"name": "new_name"}}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"user": {"domain_id": "foo1"}}, "target": {"user": {"name": "new_name"}}}
	not update.allow with input as {"credentials": {"roles": ["manager"]}, "existing": {"user": {"domain_id": "foo"}}, "target": {"user": {"name": "new_name"}}}
	not update.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"user": {"domain_id": "foo"}}, "target": {"user": {"name": "new_name"}}}
}