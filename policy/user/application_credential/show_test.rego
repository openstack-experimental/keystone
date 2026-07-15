package test_application_credential_show

import data.identity.user.application_credential.show

test_admin_allowed if {
    show.allow with input as {"credentials": {"is_admin": true}, "target": {"application_credential": {"user_id": "uid"}}}
}

test_system_reader_allowed if {
    show.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}, "target": {"application_credential": {"user_id": "uid"}}}
}

test_owner_allowed if {
    show.allow with input as {"credentials": {"user_id": "uid"}, "target": {"application_credential": {"user_id": "uid"}}}
}

test_non_owner_forbidden if {
    not show.allow with input as {"credentials": {"user_id": "other", "roles": []}, "target": {"application_credential": {"user_id": "uid"}}}
}

test_non_owner_violation if {
    v := show.violation with input as {"credentials": {"user_id": "other", "roles": []}, "target": {"application_credential": {"user_id": "uid"}}}
    count(v) == 1
    some e in v
    e.field == "user_id"
}