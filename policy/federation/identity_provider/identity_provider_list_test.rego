package test_identity_provider_list

import data.identity.federation.identity_provider.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"identity_provider": {"domain_id": "domain"}}}
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"identity_provider": {"domain_id": null}}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"identity_provider": {"domain_id": "other_domain"}}}
	not list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"identity_provider": {"domain_id": "other_domain"}}}
}
