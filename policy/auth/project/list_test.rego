package test_auth_project_list

import data.identity.auth.project.list

test_allowed if {
    list.allow with input as {"credentials": {"roles": ["admin"]}}
    list.allow with input as {"credentials": {"roles": ["reader"], "system_scope": "all"}}
    list.allow with input as {"credentials": {"roles": []}}
    list.allow with input as {"credentials": {"roles": ["reader"]}}
}