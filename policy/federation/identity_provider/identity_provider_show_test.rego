package test_identity_provider_show

import data.identity.federation.identity_provider.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"identity_provider": {"domain_id": "domain"}}}
	show.allow with input as {"credentials": {"roles": ["reader"]}, "target": {"identity_provider": {"domain_id": null}}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"identity_provider": {"domain_id": "other_domain"}}}
	not show.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"identity_provider": {"domain_id": "other_domain"}}}
}
