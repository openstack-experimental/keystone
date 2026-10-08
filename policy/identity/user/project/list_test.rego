package test_user_project_list

import data.identity.user.project.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"user": {"id": "u", "domain_id": "foo"}}}
	list.allow with input as {"credentials": {"roles": ["member"], "user_id": "u", "is_delegated": false}, "existing": {"user": {"id": "u", "domain_id": "foo"}}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}, "existing": {"user": {"id": "u"}}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"user": {"id": "u", "domain_id": "foo2"}}}
	not list.allow with input as {"credentials": {"roles": ["reader"]}, "existing": {"user": {"id": "u", "domain_id": "foo"}}}
	not list.allow with input as {"credentials": {"roles": ["member"], "user_id": "other", "is_delegated": false}, "existing": {"user": {"id": "u", "domain_id": "foo"}}}
}

# A delegated caller (application credential / trust) must not use the
# "user itself" shortcut even though `user_id` matches.
test_delegated_owner_forbidden if {
	not list.allow with input as {"credentials": {"roles": ["member"], "user_id": "u", "is_delegated": true, "project_id": "p", "delegated_project_id": "p"}, "existing": {"user": {"id": "u", "domain_id": "foo"}}}
}

# Scope-drift tripwire (security-model I3): the scope no longer matches the
# delegation's own project, so the delegated caller is refused.
test_scope_drift_forbidden if {
	not list.allow with input as {"credentials": {"roles": ["member"], "user_id": "u", "is_delegated": true, "project_id": "scope-p", "delegated_project_id": "delegation-p"}, "existing": {"user": {"id": "u", "domain_id": "foo"}}}
}

# A missing user (`existing.user` is null) must not be readable by anyone but
# an admin, so the 404 can not be used as a user-existence oracle.
test_missing_user_forbidden_for_non_admin if {
	not list.allow with input as {"credentials": {"roles": ["member"], "user_id": "u", "is_delegated": false}, "existing": {"user": null}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"user": null}}
}

test_missing_user_allowed_for_admin if {
	list.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"user": null}}
}
