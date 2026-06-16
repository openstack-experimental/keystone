package test_role_imply_rule_list

import data.identity.role.imply_rule.list

test_allowed_if_admin if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
}

test_allowed_with_is_admin if {
	list.allow with input as {"credentials": {"roles": [], "is_admin": true}}
}

test_allowed_with_reader_system_all if {
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["reader"]}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "system": "foo"}}
}
