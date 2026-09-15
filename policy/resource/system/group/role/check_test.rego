package test_system_group_role_check

import data.identity.system.group.role.check

test_allowed if {
        check.allow with input as {"credentials": {"roles": ["admin"]}}
        check.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
}

test_forbidden if {
        not check.allow with input as {"credentials": {"roles": []}}
        not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}}
        not check.allow with input as {"credentials": {"roles": ["manager"], "system": "all"}}
        not check.allow with input as {"credentials": {"roles": ["reader"], "system": "non-all"}}
}