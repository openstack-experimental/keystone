# METADATA
# description: Common policies for token operations
package identity.token

import data.identity

foreign_token_restriction if {
	token_restriction_domain_id != null
	token_restriction_domain_id != input.credentials.domain_id
}

own_token_restriction if {
	token_restriction_domain_id != null
	token_restriction_domain_id == input.credentials.domain_id
}

# Resolve token restriction domain_id from target or existing, depending
# on the operation (create/show/delete vs update).
token_restriction_domain_id := input.target.restriction.domain_id if {
	input.target.restriction.domain_id
}

token_restriction_domain_id := input.existing.restriction.domain_id if {
	input.existing.restriction.domain_id
}
