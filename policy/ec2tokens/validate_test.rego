package test_ec2tokens_validate

import data.identity.ec2tokens.validate

test_allowed if {
	validate.allow with input as {"credentials": {"roles": ["admin"]}}
	validate.allow with input as {"credentials": {"roles": ["service"]}}
}

test_forbidden if {
	not validate.allow with input as {"credentials": {"roles": ["member"]}}
	not validate.allow with input as {"credentials": {"roles": []}}
}
