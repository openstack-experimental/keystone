package test_project_show

import data.identity.resource.project.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"project": {"domain_id": "foo"}}}
}

test_not_allowed if {
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["manager"]}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"project": {"domain_id": "bar"}}}
}

# Hierarchy relatives (parents/subtree) are checked one by one with the same
# policy, each relative being passed as `existing.project`.
test_hierarchy_relatives_filtered_per_item if {
	creds := {"roles": ["reader"], "domain_id": "foo"}
	show.allow with input as {"credentials": creds, "existing": {"project": {"id": "p1", "domain_id": "foo", "parent_id": "foo"}}}
	show.allow with input as {"credentials": creds, "existing": {"project": {"id": "p2", "domain_id": "foo", "parent_id": "p1"}}}
	not show.allow with input as {"credentials": creds, "existing": {"project": {"id": "foo", "domain_id": "<<keystone.domain.root>>"}}}
	not show.allow with input as {"credentials": creds, "existing": {"project": {"id": "other", "domain_id": "bar", "parent_id": "bar"}}}
}

test_hierarchy_relatives_system_reader_sees_all if {
	creds := {"roles": ["reader"], "system": "all"}
	show.allow with input as {"credentials": creds, "existing": {"project": {"id": "foo", "domain_id": "<<keystone.domain.root>>"}}}
	show.allow with input as {"credentials": creds, "existing": {"project": {"id": "p1", "domain_id": "bar"}}}
}
