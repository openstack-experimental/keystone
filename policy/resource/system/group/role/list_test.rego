package test_system_group_role_list

import data.identity.system.group.role.list

test_allowed if {
        list.allow with input as {"credentials": {"roles": ["admin"]}}
        list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
}

test_forbidden if {
        not list.allow with input as {"credentials": {"roles": []}}
        not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}}
        not list.allow with input as {"credentials": {"roles": ["manager"], "system": "all"}}
        not list.allow with input as {"credentials": {"roles": ["reader"], "system": "non-all"}}
}
