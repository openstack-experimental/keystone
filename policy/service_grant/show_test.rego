package test_service_grant_show

import data.identity.service_grant.show

grant := {
	"id": "g1",
	"domain_id": "d1",
	"grantor_user_id": "u1",
	"grantee": {"type": "client", "client_id": "heat", "client_domain_id": "infra"},
	"target": {"type": "project", "project_id": "p1", "project_domain_id": "d2"},
}

user(extra) := object.union(
	{
		"user_id": "u9",
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

check(creds) if {
	show.allow with input as {"credentials": creds, "target": {"service_grant": null}, "existing": {"service_grant": grant}}
}

test_admin if {
	check(user({"roles": ["admin"]}))
}

test_grantor if {
	check(user({"user_id": "u1"}))
}

test_project_manager if {
	check(user({"roles": ["manager"], "project_id": "p1"}))
	not check(user({"roles": ["manager"], "project_id": "p2"}))
	not check(user({"roles": ["member"], "project_id": "p1"}))
}

test_domain_manager if {
	# The grantor's domain and the project's domain.
	check(user({"roles": ["manager"], "domain_id": "d1"}))
	check(user({"roles": ["manager"], "domain_id": "d2"}))
	not check(user({"roles": ["manager"], "domain_id": "d3"}))
}

test_stranger_denied if {
	not check(user({}))
	not check(user({"project_id": "p1"}))
}

test_grantee_service if {
	check(user({"user_id": "x", "roles": [], "auth_type": "service_client", "actor": {"client_id": "heat", "spiffe_id": "spiffe://td/heat"}}))
	not check(user({"user_id": "x", "roles": [], "auth_type": "service_client", "actor": {"client_id": "nova", "spiffe_id": "spiffe://td/nova"}}))
}

# A delegated grantor is held to its delegation project, with the scope
# pinned to it.
test_delegated_grantor_bound_to_project if {
	check(user({"user_id": "u1", "is_delegated": true, "auth_type": "application_credential", "project_id": "p1", "delegated_project_id": "p1"}))
	not check(user({"user_id": "u1", "is_delegated": true, "auth_type": "application_credential", "project_id": "p2", "delegated_project_id": "p2"}))
	not check(user({"user_id": "u1", "is_delegated": true, "auth_type": "application_credential", "project_id": "p1", "delegated_project_id": "p2"}))
}

# A request made under a service grant never manages grants, not even
# with the admin role or as the grantor.
test_under_service_grant_denied if {
	not check(user({"user_id": "u1", "roles": ["admin"], "is_delegated": true, "auth_type": "service_grant", "project_id": "p1", "delegated_project_id": "p1", "service_grant_id": "g1", "actor": {"client_id": "heat", "spiffe_id": "spiffe://td/heat"}}))
}

# A service acting for a user is not the grantor, even with its user id.
test_actor_is_not_grantor if {
	not check(user({"user_id": "u1", "auth_type": "service_client", "actor": {"client_id": "nova", "spiffe_id": "spiffe://td/nova"}}))
}

# A missing grant (id only) is visible to admins only, which then 404.
test_missing_grant if {
	show.allow with input as {"credentials": user({"roles": ["admin"]}), "existing": {"service_grant": {"id": "g1"}}}
	not show.allow with input as {"credentials": user({"user_id": "u1"}), "existing": {"service_grant": {"id": "g1"}}}
}
