package test_os_ec2_read_credential

import data.identity.os_ec2.read_credential

test_allowed if {
	read_credential.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"user_id": "other"}}
	read_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"user_id": "u1"}}
	read_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"user_id": "u1", "credential": {"access": "AKIA123"}}}
}

test_forbidden if {
	not read_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"user_id": "other"}}
	not read_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"user_id": "other", "credential": {"access": "AKIA123"}}}
	not read_credential.allow with input as {"credentials": {"roles": []}, "target": {"user_id": "u1"}}
}
