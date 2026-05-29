package test_mapping_list

import data.identity.federation.mapping.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": "domain"}}}
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": null}}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": "other_domain"}}}
	not list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": "other_domain"}}}
}
