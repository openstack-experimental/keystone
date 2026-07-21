package test_application_credential_create

import data.identity.user.application_credential.create

test_owner_allowed if {
    create.allow with input as {
        "credentials": {"user_id": "uid"},
        "target": {"application_credential": {"user_id": "uid"}},
    }
}

test_owner_no_violation if {
    count(create.violation) == 0 with input as {
        "credentials": {"user_id": "uid"},
        "target": {"application_credential": {"user_id": "uid"}},
    }
}

test_non_owner_forbidden if {
    not create.allow with input as {
        "credentials": {"user_id": "other"},
        "target": {"application_credential": {"user_id": "uid"}},
    }
}

test_non_owner_violation if {
    violation := create.violation with input as {
        "credentials": {"user_id": "other"},
        "target": {"application_credential": {"user_id": "uid"}},
    }
    count(violation) == 1
    some v in violation
    v.field == "user_id"
}