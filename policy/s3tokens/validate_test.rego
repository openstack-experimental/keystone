package test_s3tokens_validate

import data.identity.s3tokens.validate

test_allowed if {
	validate.allow with input as {"credentials": {"roles": ["admin"]}}
	validate.allow with input as {"credentials": {"roles": ["service"]}}
}

test_forbidden if {
	not validate.allow with input as {"credentials": {"roles": ["member"]}}
	not validate.allow with input as {"credentials": {"roles": []}}
}
