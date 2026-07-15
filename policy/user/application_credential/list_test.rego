package test_application_credential_list

import data.identity.user.application_credential.list

test_admin_allowed if {
    list.allow with input as {"credentials": {"is_admin": true}, "target": {"application_credential": {"user_id": "uid"}}}
}

test_system_reader_allowed if {
    list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}, "target": {"application_credential": {"user_id": "uid"}}}
}

test_owner_allowed if {
    list.allow with input as {"credentials": {"user_id": "uid"}, "target": {"application_credential": {"user_id": "uid"}}}
}

test_non_owner_forbidden if {
    not list.allow with input as {"credentials": {"user_id": "other", "roles": []}, "target": {"application_credential": {"user_id": "uid"}}}
}

test_non_owner_violation if {
    v := list.violation with input as {"credentials": {"user_id": "other", "roles": []}, "target": {"application_credential": {"user_id": "uid"}}}
    count(v) == 1
    some e in v
    e.field == "user_id"
}