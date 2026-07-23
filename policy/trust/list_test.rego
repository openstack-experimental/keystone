package test_trust_list

import data.identity.trust.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"trust": {}}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}, "target": {"trust": {}}}
	list.allow with input as {"credentials": {"roles": ["member"]}, "target": {"trust": {}}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}, "target": {"trust": {}}}
}
