package test_os_ec2_create_credential

import data.identity.os_ec2.create_credential

test_allowed if {
	create_credential.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"user_id": "other", "tenant_id": "pid"}}
	create_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"user_id": "u1", "tenant_id": "pid"}}
}

test_forbidden if {
	not create_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"user_id": "other", "tenant_id": "pid"}}
	not create_credential.allow with input as {"credentials": {"roles": []}, "target": {"user_id": "u1", "tenant_id": "pid"}}
}
