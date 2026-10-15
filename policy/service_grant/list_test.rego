package test_service_grant_list

import data.identity.service_grant.list

user(extra) := object.union(
	{
		"user_id": "u1",
		"roles": ["member"],
		"is_delegated": false,
		"auth_type": "password",
		"project_id": null,
		"domain_id": null,
		"delegated_project_id": null,
		"actor": null,
		"service_grant_id": null,
	},
	extra,
)

check(creds, filters) if {
	list.allow with input as {"credentials": creds, "target": {"service_grant": filters}}
}

test_admin_unfiltered if {
	check(user({"roles": ["admin"]}), {})
}

test_unfiltered_denied if {
	not check(user({}), {})
	not check(user({"roles": ["manager"], "project_id": "p1"}), {})
}

test_own_grants if {
	check(user({}), {"user_id": "u1"})
	not check(user({}), {"user_id": "u2"})
}

test_project_manager if {
	check(user({"roles": ["manager"], "project_id": "p1"}), {"project_id": "p1"})
	not check(user({"roles": ["manager"], "project_id": "p1"}), {"project_id": "p2"})
	not check(user({"project_id": "p1"}), {"project_id": "p1"})
}

test_domain_manager if {
	check(user({"roles": ["manager"], "domain_id": "d1"}), {"domain_id": "d1"})
	not check(user({"roles": ["manager"], "domain_id": "d1"}), {"domain_id": "d2"})
}

test_delegated_own_grants_bound_to_project if {
	creds := user({"is_delegated": true, "auth_type": "application_credential", "project_id": "p1", "delegated_project_id": "p1"})
	check(creds, {"user_id": "u1", "project_id": "p1"})
	not check(creds, {"user_id": "u1"})
	not check(creds, {"user_id": "u1", "project_id": "p2"})
}

test_grantee_service_cannot_list if {
	not check(user({"user_id": "x", "roles": [], "auth_type": "service_client", "actor": {"client_id": "heat", "spiffe_id": "spiffe://td/heat"}}), {"grantee_client_id": "heat"})
}

test_under_service_grant_denied if {
	not check(user({"roles": ["admin"], "is_delegated": true, "auth_type": "service_grant", "project_id": "p1", "delegated_project_id": "p1", "service_grant_id": "g1", "actor": {"client_id": "heat", "spiffe_id": "spiffe://td/heat"}}), {"project_id": "p1"})
}
