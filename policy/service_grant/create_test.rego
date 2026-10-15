package test_service_grant_create

import data.identity.service_grant.create

target := {"service_grant": {"grantee_client_id": "heat", "project_id": "p1"}}

user(extra) := object.union(
	{
		"user_id": "u1",
		"roles": ["member"],
		"is_delegated": false,
		"auth_type": "password",
		"project_id": "p1",
		"delegated_project_id": null,
		"unrestricted": null,
		"actor": null,
		"service_grant_id": null,
	},
	extra,
)

check(creds) if {
	create.allow with input as {"credentials": creds, "target": target}
}

test_user_may_create if {
	check(user({}))

	# No role requirement: the provider bounds the grant by the caller's
	# own roles on the project.
	check(user({"roles": []}))
}

test_trust_denied if {
	not check(user({"is_delegated": true, "auth_type": "trust", "delegated_project_id": "p1"}))
}

test_restricted_application_credential_denied if {
	not check(user({"is_delegated": true, "auth_type": "application_credential", "unrestricted": false, "delegated_project_id": "p1"}))
}

test_unrestricted_application_credential_on_own_project if {
	check(user({"is_delegated": true, "auth_type": "application_credential", "unrestricted": true, "delegated_project_id": "p1"}))
	not check(user({"is_delegated": true, "auth_type": "application_credential", "unrestricted": true, "project_id": "p2", "delegated_project_id": "p2"}))
}

test_rescoped_delegated_token_denied if {
	# A token carried forward from a trust stays delegated.
	not check(user({"is_delegated": true, "auth_type": "token"}))
}

test_service_grant_denied if {
	not check(user({"is_delegated": true, "auth_type": "service_grant", "delegated_project_id": "p1", "service_grant_id": "g1", "actor": {"client_id": "heat", "spiffe_id": "spiffe://td/heat"}}))
}

test_service_client_denied if {
	not check(user({"user_id": "x", "auth_type": "service_client", "actor": {"client_id": "heat", "spiffe_id": "spiffe://td/heat"}}))
}
