# METADATA
# description: Common policies for federation management
package identity.federation

import data.identity

any_domain_id := input.target.identity_provider.domain_id if {
	input.target.identity_provider.domain_id
}

any_domain_id := input.target.mapping.domain_id if {
	input.target.mapping.domain_id
}

global_idp if {
	not input.target.identity_provider.domain_id
}

global_idp if {
	input.target.identity_provider.domain_id == null
}

own_idp if {
	input.target.identity_provider.domain_id != null
	input.target.identity_provider.domain_id == input.credentials.domain_id
}

foreign_idp if {
	input.target.identity_provider.domain_id != null
	input.target.identity_provider.domain_id != input.credentials.domain_id
}

global_mapping if {
	not input.target.mapping.domain_id
}

global_mapping if {
	input.target.mapping.domain_id == null
}

own_mapping if {
	input.target.mapping.domain_id != null
	input.target.mapping.domain_id == input.credentials.domain_id
}

foreign_mapping if {
	input.target.mapping.domain_id != null
	input.target.mapping.domain_id != input.credentials.domain_id
}
