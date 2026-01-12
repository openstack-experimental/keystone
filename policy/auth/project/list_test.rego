package test_auth_project_list

import data.identity.auth.project.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system_scope": "all"}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": ["reader"], "system_scope": "not_all"}}
}
