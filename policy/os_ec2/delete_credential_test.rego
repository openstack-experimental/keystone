package test_os_ec2_delete_credential

import data.identity.os_ec2.delete_credential

test_allowed if {
	delete_credential.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"user_id": "other", "credential": {"access": "AKIA123"}}}
	delete_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"user_id": "u1", "credential": {"access": "AKIA123"}}}
}

test_forbidden if {
	not delete_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"user_id": "other", "credential": {"access": "AKIA123"}}}
	not delete_credential.allow with input as {"credentials": {"roles": []}, "existing": {"user_id": "u1", "credential": {"access": "AKIA123"}}}
}
