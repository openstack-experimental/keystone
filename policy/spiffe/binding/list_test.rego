package test_spiffe_binding_list

import data.identity.spiffe.binding.list

test_allowed if {
	# Admin role can list bindings.
	list.allow with input as {"credentials": {"roles": ["admin"]}}

	# Admin (is_admin flag) can list bindings.
	list.allow with input as {"credentials": {"roles": [], "is_admin": true}}

	# System user (system == "all") with member role can list bindings.
	list.allow with input as {"credentials": {"roles": ["member"], "system": "all"}}

	# Owner with reader role can list bindings.
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"binding": {"domain_id": "domain"}}}

	# List with no domain_id filter and reader role - allowed.
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"binding": {"domain_id": null}}}

	# Admin can list bindings for any domain.
	list.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"binding": {"domain_id": null}}}
}

test_forbidden if {
	# No roles - forbidden.
	not list.allow with input as {"credentials": {"roles": []}}

	# Reader role in a different domain - forbidden.
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"binding": {"domain_id": "other_domain"}}}

	# Member role in a different domain - forbidden.
	not list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"binding": {"domain_id": "other_domain"}}}

	# No roles and no domain scope - forbidden.
	not list.allow with input as {"credentials": {"roles": []}, "target": {"binding": {"domain_id": "domain"}}}
}
