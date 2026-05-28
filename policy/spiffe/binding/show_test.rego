package test_spiffe_binding_show

import data.identity.spiffe.binding.show

test_allowed if {
	# Admin role can show bindings.
	show.allow with input as {"credentials": {"roles": ["admin"]}}

	# Admin (is_admin flag) can show bindings.
	show.allow with input as {"credentials": {"roles": [], "is_admin": true}}

	# System user (system == "all") with member role can show bindings.
	show.allow with input as {"credentials": {"roles": ["member"], "system": "all"}}

	# Owner with reader role can show bindings.
	show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "existing": {"binding": {"domain_id": "domain"}}}

	# Owner with reader and manager roles can show bindings.
	show.allow with input as {"credentials": {"roles": ["reader", "manager"], "domain_id": "domain"}, "existing": {"binding": {"domain_id": "domain"}}}

	# Admin can show bindings for any domain.
	show.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"binding": {"domain_id": null}}}
}

test_forbidden if {
	# No roles - forbidden.
	not show.allow with input as {"credentials": {"roles": []}}

	# Reader role in a different domain - forbidden.
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "existing": {"binding": {"domain_id": "other_domain"}}}

	# Manager role in a different domain - forbidden.
	not show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "existing": {"binding": {"domain_id": "other_domain"}}}

	# No roles and no domain scope - forbidden.
	not show.allow with input as {"credentials": {"roles": []}, "existing": {"binding": {"domain_id": "domain"}}}
}
