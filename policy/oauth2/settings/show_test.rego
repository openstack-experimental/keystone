package test_oauth2_settings_show

import data.identity.oauth2.settings.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"oauth2_settings": {"domain_id": "foo"}}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"oauth2_settings": {"domain_id": "foo1"}}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"oauth2_settings": {"domain_id": "foo"}}}
}

test_violation_foreign_domain if {
	show.violation[{"field": "domain_id", "msg": "showing the OAuth2 settings of another domain requires `admin` role."}] with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"oauth2_settings": {"domain_id": "foo1"}}}
}
