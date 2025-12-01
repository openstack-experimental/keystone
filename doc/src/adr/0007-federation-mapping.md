# 7. Federation Mapping

Date: 2025-11-03

## Status

Accepted

## Context

OIDC protocol describes how the user data is being passed to the service
provider. It is necessary to translate this information to the Keystone data
model. In v3 "mapping" is being used to describe this translation. The data
model of the v3 mapping is, however, unnecessary complex (due to historical
reasons). HashiCorp vault describes "mapping"s as "roles" for such translations.
Since it is not possible to use the term "role" the mapping should continue to
be used instead. The model of the Vault role provides a nice and easy reference
for Keystone.

## Decision

"Mapping" (attribute mapping) MUST describe how the information from OIDC claims
need to be translated into the Keystone data model. It MUST also describe user
defined bounds to allow use restriction.

When `domain_id` is not being set on the IdP level it MUST be defined either on
the mapping entry, or the mapping MUST define `domain_id_claim` to extract the
information about domain relation of the user. `domain_id` MUST be immutable
property of the mapping to prevent moving it to the foreign domain.

Mapping MUST have the `name` attribute that is unique within the domain.

`default_mapping_name` property SHOULD be specified on the IdP level to provide
a default for when the user does not explicitly specify which mapping should be
used.

## Consequences

- Mappings MUST be configured carefully to prevent login of users across the
  domain borders. `bound_xxx` should be used extensively to guard this.
