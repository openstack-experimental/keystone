package test_delegatable_service_list

import data.identity.delegatable_service.list

test_user_allowed if {
	list.allow with input as {"credentials": {"user_id": "u1", "roles": [], "actor": null, "service_grant_id": null}}
}

test_service_denied if {
	not list.allow with input as {"credentials": {"user_id": "x", "roles": [], "actor": {"client_id": "heat", "spiffe_id": "spiffe://td/heat"}, "service_grant_id": null}}
	not list.allow with input as {"credentials": {"user_id": "u1", "roles": [], "actor": {"client_id": "heat", "spiffe_id": "spiffe://td/heat"}, "service_grant_id": "g1"}}
}
