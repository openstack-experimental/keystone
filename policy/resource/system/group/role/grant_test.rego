package test_system_group_role_grant

import data.identity.system.group.role.grant

test_allowed if {
        grant.allow with input as {"credentials": {"roles": ["admin"]}}
        grant.allow with input as {"credentials": {"roles": ["manager"], "system": "all"}}
}

test_forbidden if {
        not grant.allow with input as {"credentials": {"roles": []}}
        not grant.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
        not grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}}
        not grant.allow with input as {"credentials": {"roles": ["member"], "system": "all"}}
}
